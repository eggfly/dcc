#!/usr/bin/env python
# coding=utf-8
import argparse
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

from pyaxmlparser import APK

from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.androconf import show_logging
from androguard.core.bytecodes import apk, dvm
from androguard.util import read
from dex2c.compiler import Dex2C
from dex2c.util import MangleForJni, JniLongName
from dex2c.util import get_method_triple, get_access_method, is_synthetic_method, is_native_method

time_str = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

APKTOOL = 'tools/apktool.jar'
ManifestEditor = 'tools/ManifestEditor-1.0.2.jar'
SIGN_JAR = 'tools/signapk.jar'
NDK_BUILD = 'ndk-build'
LIBNATIVECODE = 'libnc.so'

show_logging(level=logging.INFO)
logger = logging.getLogger('dcc')

temp_files = []


def is_windows():
    return os.name == 'nt'


def cpu_count():
    num_processes = os.cpu_count()
    if num_processes is None:
        num_processes = 2
    return num_processes


def make_temp_dir(prefix='dcc'):
    global temp_files
    tmp = tempfile.mkdtemp(prefix=prefix)
    temp_files.append(tmp)
    return tmp


def make_temp_file(suffix=''):
    global temp_files
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    temp_files.append(tmp)
    return tmp


def clean_temp_files():
    for name in temp_files:
        if not os.path.exists(name):
            continue
        logger.info('removing %s' % name)
        if os.path.isdir(name):
            shutil.rmtree(name)
        else:
            os.unlink(name)


class ApkTool(object):
    @staticmethod
    def decompile(package_name, apk):
        output_dir = make_temp_dir('dcc-apktool-' + package_name + "-" + time_str + '-')
        subprocess.check_call(['java', '-jar', APKTOOL, 'd', '-r', '--only-main-classes', '-f', '-o', output_dir, apk])
        return output_dir

    @staticmethod
    def compile(decompiled_dir):
        unsigned_apk = make_temp_file('-unsigned.apk')
        subprocess.check_call(['java', '-jar', APKTOOL, 'b', '-o', unsigned_apk, decompiled_dir])
        return unsigned_apk


def sign(unsigned_apk, signed_apk):
    pem = os.path.join('tests/testkey/testkey.x509.pem')
    pk8 = os.path.join('tests/testkey/testkey.pk8')
    logger.info("signing %s -> %s" % (unsigned_apk, signed_apk))
    subprocess.check_call(['java', '-jar', SIGN_JAR, pem, pk8, unsigned_apk, signed_apk])


def build_project(project_dir, num_processes=0):
    subprocess.check_call([NDK_BUILD, '-j%d' % cpu_count(), '-C', project_dir])


def auto_vms(filename):
    ret = androconf.is_android(filename)
    vms = {}
    if ret == 'APK':
        apk_obj = apk.APK(filename)
        for dex_file in apk_obj.get_dex_names():
            name = dex_file.rstrip(".dex")
            dex = apk_obj.get_file(dex_file)
            vms[name] = dvm.DalvikVMFormat(dex)
        return vms
    elif ret == 'DEX':
        vms["classes"] = dvm.DalvikVMFormat(read(filename))
        return vms
    elif ret == 'DEY':
        vms["classes"] = dvm.DalvikOdexVMFormat(read(filename))
        return vms
    raise Exception("unsupported file %s" % filename)


class MethodFilter(object):
    def __init__(self, configure, vm):
        self._compile_filters = []
        self._keep_filters = []
        self._compile_full_match = set()

        self.conflict_methods = set()
        self.native_methods = set()
        self.annotated_methods = set()

        self._load_filter_configure(configure)
        self._init_conflict_methods(vm)
        self._init_native_methods(vm)
        self._init_annotation_methods(vm)

    def _load_filter_configure(self, configure):
        if not os.path.exists(configure):
            return

        with open(configure) as fp:
            for line in fp:
                line = line.strip()
                if not line or line[0] == '#':
                    continue

                if line[0] == '!':
                    line = line[1:].strip()
                    self._keep_filters.append(re.compile(line))
                elif line[0] == '=':
                    line = line[1:].strip()
                    self._compile_full_match.add(line)
                else:
                    self._compile_filters.append(re.compile(line))

    def _init_conflict_methods(self, vm):
        all_methods = {}
        for m in vm.get_methods():
            method_triple = get_method_triple(m, return_type=False)
            if method_triple in all_methods:
                self.conflict_methods.add(m)
                self.conflict_methods.add(all_methods[method_triple])
            else:
                all_methods[method_triple] = m

    def _init_native_methods(self, vm):
        for m in vm.get_methods():
            cls_name, name, _ = get_method_triple(m)

            access = get_access_method(m.get_access_flags())
            if 'native' in access:
                self.native_methods.add((cls_name, name))

    def _add_annotation_method(self, method):
        if not is_synthetic_method(method) and not is_native_method(method):
            self.annotated_methods.add(method)

    def _init_annotation_methods(self, vm):
        for c in vm.get_classes():
            adi_off = c.get_annotations_off()
            if adi_off == 0:
                continue

            adi = vm.CM.get_obj_by_offset(adi_off)
            annotated_class = False
            # ref:https://github.com/androguard/androguard/issues/175
            if adi.get_class_annotations_off() != 0:
                ann_set_item = vm.CM.get_obj_by_offset(adi.get_class_annotations_off())
                for aoffitem in ann_set_item.get_annotation_off_item():
                    annotation_item = vm.CM.get_obj_by_offset(aoffitem.get_annotation_off())
                    encoded_annotation = annotation_item.get_annotation()
                    type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                    if type_desc.endswith('Dex2C;'):
                        annotated_class = True
                        for method in c.get_methods():
                            self._add_annotation_method(method)
                        break

            if not annotated_class:
                for mi in adi.get_method_annotations():
                    method = vm.get_method_by_idx(mi.get_method_idx())
                    ann_set_item = vm.CM.get_obj_by_offset(mi.get_annotations_off())

                    for aoffitem in ann_set_item.get_annotation_off_item():
                        annotation_item = vm.CM.get_obj_by_offset(aoffitem.get_annotation_off())
                        encoded_annotation = annotation_item.get_annotation()
                        type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                        if type_desc.endswith('Dex2C;'):
                            self._add_annotation_method(method)

    def should_compile(self, method):
        # don't compile functions that have same parameter but differ return type
        if method in self.conflict_methods:
            return False

        # synthetic method
        if is_synthetic_method(method) or is_native_method(method):
            return False

        method_triple = get_method_triple(method)
        cls_name, name, _ = method_triple

        if name == "<clinit>" or name == "<init>":
            # do not compile constructor
            return False

        # Android VM may find the wrong method using short jni name
        # don't compile function if there is a same named native method
        if (cls_name, name) in self.native_methods:
            return False

        full_name = ''.join(method_triple)
        for rule in self._keep_filters:
            if rule.search(full_name):
                # logging.info("filter rule " + str(rule) + " matched: " + full_name)
                return False

        if full_name in self._compile_full_match:
            return True

        if method in self.annotated_methods:
            return True

        for rule in self._compile_filters:
            if rule.search(full_name):
                return True

        return False


def copy_compiled_libs(project_dir, decompiled_dir):
    compiled_libs_dir = os.path.join(project_dir, "libs")
    decompiled_libs_dir = os.path.join(decompiled_dir, "lib")
    if not os.path.exists(compiled_libs_dir):
        return
    if not os.path.exists(decompiled_libs_dir):
        shutil.copytree(compiled_libs_dir, decompiled_libs_dir)
        return

    for abi in os.listdir(decompiled_libs_dir):
        dst = os.path.join(decompiled_libs_dir, abi)
        src = os.path.join(compiled_libs_dir, abi)
        if not os.path.exists(src) and abi == 'armeabi':
            src = os.path.join(compiled_libs_dir, 'armeabi-v7a')
            logger.warning('Use armeabi-v7a for armeabi')

        if not os.path.exists(src):
            raise Exception("ABI %s is not supported!" % abi)

        libnc = os.path.join(src, LIBNATIVECODE)
        shutil.copy(libnc, dst)


def native_class_methods(smali_path, compiled_methods):
    def next_line():
        return fp.readline()

    def handle_annotation():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            code_lines.append(line)
            if s == '.end annotation':
                break
            else:
                continue

    def handle_method_body():
        while True:
            line = next_line()
            if not line:
                break
            s = line.strip()
            if s == '.end method':
                break
            elif line.startswith('    .annotation') and s.find('Dex2C') < 0:
                code_lines.append(line)
                handle_annotation()
            else:
                continue

    code_lines = []
    class_name = ''
    with open(smali_path, 'r') as fp:
        while True:
            line = next_line()
            if not line:
                break
            code_lines.append(line)
            line = line.strip()
            if line.startswith('.class'):
                class_name = line.split(' ')[-1]
            elif line.startswith('.method'):
                current_method = line.split(' ')[-1]
                param = current_method.find('(')
                name, proto = current_method[:param], current_method[param:]
                if (class_name, name, proto) in compiled_methods:
                    if line.find(' native ') < 0:
                        code_lines[-1] = code_lines[-1].replace(current_method, 'native ' + current_method)
                    handle_method_body()
                    code_lines.append('.end method\n')

    with open(smali_path, 'w') as fp:
        fp.writelines(code_lines)


def native_compiled_dexes(decompiled_dir, compiled_methods):
    # smali smali_classes2 smali_classes3 ...
    classes_output = list(filter(lambda x: x.find('smali') >= 0, os.listdir(decompiled_dir)))
    todo = []
    for classes in classes_output:
        for method_triple in compiled_methods:
            cls_name, name, proto = method_triple
            cls_name = cls_name[1:-1]  # strip L;
            smali_path = os.path.join(decompiled_dir, classes, cls_name) + '.smali'
            if os.path.exists(smali_path):
                todo.append(smali_path)

    for smali_path in todo:
        native_class_methods(smali_path, compiled_methods)


def write_compiled_methods(project_dir, classes_prefix, compiled_methods):
    logger.info("start write cpp --> " + project_dir)
    class_to_methods_dict = {}
    source_dir = os.path.join(project_dir, 'jni', 'nc')
    if not os.path.exists(source_dir):
        os.makedirs(source_dir)
    for method_triple, code in compiled_methods.items():
        cls_name, method_name, signature = method_triple
        assert cls_name[0] == 'L'
        assert cls_name[-1] == ';'
        cls_name = cls_name[1:-1]
        package_name = "/".join(cls_name.split("/")[:-1])
        if package_name != "":
            mangled_package_name = MangleForJni(package_name)
        else:
            mangled_package_name = "__default_package_name__"
        if mangled_package_name not in class_to_methods_dict:
            # one package name, multiple groups of codes
            class_to_methods_dict[mangled_package_name] = [[]]
        # full_name = JniLongName(*method_triple)
        if len(class_to_methods_dict[mangled_package_name][-1]) > 1000:
            # split to multiple files
            class_to_methods_dict[mangled_package_name].append([])
        class_to_methods_dict[mangled_package_name][-1].append(code)
    for file_name, code_groups in class_to_methods_dict.items():
        for idx, codes in enumerate(code_groups):
            file_path = os.path.join(source_dir, classes_prefix + "_" + file_name + "_" + str(idx)) + '.cpp'
            if os.path.exists(file_path):
                logger.warning("Overwrite file %s" % file_path)
            with open(file_path, 'w') as fp:
                fp.write('#include "Dex2C.h"\n\n\n')
                for code in codes:
                    fp.write("\n\n\n")
                    fp.write(code)
                    fp.write("\n\n\n")
    logger.info("write all cpp done! --> " + source_dir)
    with open(os.path.join(source_dir, 'compiled_methods.txt'), 'w') as fp:
        fp.write('\n'.join(list(map(''.join, compiled_methods.keys()))))


def archive_compiled_code(project_dir):
    outfile = make_temp_file('-dcc')
    outfile = shutil.make_archive(outfile, 'zip', project_dir)
    return outfile


def compile_dex(vm, filter_cfg):
    vmx = analysis.Analysis(vm)
    method_filter = MethodFilter(filter_cfg, vm)
    compiler = Dex2C(vm, vmx)

    compiled_method_code = {}
    errors = []

    for m in vm.get_methods():
        method_triple = get_method_triple(m)

        jni_longname = JniLongName(*method_triple)
        full_name = ''.join(method_triple)

        if len(jni_longname) > 220:
            logger.debug("name to long %s(> 220) %s" % (jni_longname, full_name))
            continue

        if method_filter.should_compile(m):
            logger.debug("compiling %s" % full_name)
            try:
                code = compiler.get_source_method(m)
            except Exception as e:
                logger.warning("compile method failed:%s (%s)" % (full_name, str(e)), exc_info=True)
                errors.append('%s:%s' % (full_name, str(e)))
                continue

            if code:
                code_bytes = bytes(code, "utf-8")
                compiled_method_code[method_triple] = code

    return compiled_method_code, errors


def compile_and_save_code(apk_file, project_dir, filter_cfg):
    logger.info("--> start reading all dex from " + apk_file)
    vms = auto_vms(apk_file)
    compiled_methods = set()
    for classes_prefix, vm in vms.items():
        logger.info("--> start compile_dex: %s.dex %s" % (classes_prefix, str(vm)))
        codes, errors = compile_dex(vm, filter_cfg)
        compiled_methods.update(codes.keys())
        if errors:
            logger.warning('================================')
            logger.warning('\n'.join(errors))
            logger.warning('================================')
        # write_methods
        logger.info("--> start write_compiled_methods: %s.dex codes=%d" % (classes_prefix, len(codes)))
        write_compiled_methods(project_dir, classes_prefix, codes)
    return compiled_methods


def is_apk(name):
    return name.endswith('.apk')


def get_super_cls_name_from_smali(decompiled_dir, cls_name):
    cls_class_parts = cls_name.split(".")
    smali_file = os.path.join(decompiled_dir, "smali", *cls_class_parts) + ".smali"
    if not os.path.isfile(smali_file):
        logger.warning(smali_file + " is not a file")
        return None
    with open(smali_file) as fp:
        while True:
            line = fp.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith(".super"):
                super_cls_l_name = line.split(" ")[-1]
                assert super_cls_l_name[0] == 'L'
                assert super_cls_l_name[-1] == ';'
                super_cls_name = super_cls_l_name[1:-1].replace("/", ".")
                return super_cls_name
    return None


def copy_kvm_smali_dir(decompiled_dir):
    smali_kvm_dir = os.path.join(decompiled_dir, "smali", "kvm")
    if not os.path.exists(smali_kvm_dir):
        shutil.copytree("kvm", smali_kvm_dir)
    else:
        logger.warning("kvm already exist??")


def dcc_main(apk_file, filtercfg, outapk, do_compile=True, project_dir=None, source_archive='project-source.zip'):
    if not os.path.exists(apk_file):
        logger.error("file %s is not exists", apk_file)
        return

    parse_apk = APK(apk_file)
    package_name = parse_apk.packagename

    # initialize project dir structure
    if project_dir:
        if not os.path.exists(project_dir):
            shutil.copytree('project', project_dir)
    else:
        project_dir = make_temp_dir('dcc-project-' + package_name + "-" + time_str + '-')
        shutil.rmtree(project_dir)
        shutil.copytree('project', project_dir)

    compiled_methods = compile_and_save_code(apk_file, project_dir, filtercfg)

    if len(compiled_methods) == 0:
        logger.warning("no compiled methods")
        return

    # zip
    src_zip = archive_compiled_code(project_dir)
    shutil.move(src_zip, source_archive)

    if do_compile:
        build_project(project_dir)

    if is_apk(apk_file) and outapk:
        decompiled_dir = ApkTool.decompile(package_name, apk_file)
        native_compiled_dexes(decompiled_dir, compiled_methods)
        logging.info("copy_compiled_libs to " + decompiled_dir)
        copy_compiled_libs(project_dir, decompiled_dir)
        # modified
        insert_init_code(decompiled_dir, package_name, parse_apk)
        logger.info("copy kvm smali dir...")
        copy_kvm_smali_dir(decompiled_dir)
        unsigned_apk = ApkTool.compile(decompiled_dir)
        sign(unsigned_apk, outapk)


def insert_init_code(decompiled_dir, package_name, parse_apk):
    current_app_cls_name = parse_apk.get_attribute_value("application", "name")
    current_app_component_factory_cls_name = parse_apk.get_attribute_value("application", "appComponentFactory")
    if not current_app_cls_name and not current_app_component_factory_cls_name:
        # both empty
        insert_new_app_cls(decompiled_dir)
    else:
        # appComponentFactory first
        if current_app_component_factory_cls_name is not None:
            cls_name = current_app_component_factory_cls_name
        else:
            cls_name = current_app_cls_name
        if cls_name.startswith("."):
            cls_name = package_name + cls_name
        smali_file = find_app_smali(cls_name, decompiled_dir)
        if smali_file is None:
            logger.warning(
                "** need some more check ** app %s declared, but class not exists, insert new app class." % cls_name)
            insert_new_app_cls(decompiled_dir)
        else:
            modify_existed_app_or_factory_class(cls_name, decompiled_dir)


def insert_new_app_cls(decompiled_dir):
    # TODO: need insert a new app class into AndroidManifest.xml
    binary_manifest = os.path.join(decompiled_dir, "AndroidManifest.xml")
    modified_binary_manifest = os.path.join(decompiled_dir, "AndroidManifest-app.xml")
    subprocess.check_call(
        ['java', '-jar', ManifestEditor, binary_manifest, "-an", "kvm.MyApp", "-o",
         modified_binary_manifest])
    os.remove(binary_manifest)
    os.rename(modified_binary_manifest, binary_manifest)
    logging.info("binary AndroidManifest.xml written: " + binary_manifest)


def modify_existed_app_or_factory_class(cls_name, decompiled_dir):
    while True:
        super_app_cls_name = get_super_cls_name_from_smali(decompiled_dir, cls_name)
        logging.info("get super class: %s" % super_app_cls_name)
        if super_app_cls_name is None \
                or super_app_cls_name == "android.app.Application" \
                or super_app_cls_name == "android.app.AppComponentFactory":
            break
        cls_name = super_app_cls_name
    if cls_name is None:
        logger.warning("current_app_cls_name is None")
    else:
        insert_init_code_to_smali(cls_name, decompiled_dir)
        logger.info("smali initialize code modifications complete!")


def insert_init_code_to_smali(app_cls_name, decompiled_dir):
    found_smali_file = find_app_smali(app_cls_name, decompiled_dir)
    assert found_smali_file is not None
    logging.info("try to modify smali code for most super app class: " + found_smali_file)
    modified_smali_lines = []
    clinit_start = clinit_locals_start = nc_init_inserted = False
    with open(found_smali_file) as fp:
        while True:
            line = fp.readline()
            if not line:
                break
            modified_smali_lines.append(line)
            line = line.strip()
            if line.startswith(".method") and line.endswith("<clinit>()V"):
                logger.info("found smali line: " + line)
                clinit_start = True
            if clinit_start and line.startswith(".locals"):
                clinit_locals_start = True
            if clinit_start and clinit_locals_start:
                logger.info("found and insert invoke code to the <clinit> function")
                modified_smali_lines.append("\n    invoke-static {}, Lkvm/NcInit;->setup()V\n")
                clinit_start = clinit_locals_start = False
                nc_init_inserted = True
    if not nc_init_inserted:
        logger.info("<clinit> not found, add a new <clinit> function at tail")
        modified_smali_lines.append("""
    .method static constructor <clinit>()V
        .locals 0

        invoke-static {}, Lkvm/NcInit;->setup()V

        return-void
    .end method
    """)
    # write lines
    with open(found_smali_file, "w") as fp:
        fp.writelines(modified_smali_lines)


def find_app_smali(app_cls_name, decompiled_dir):
    most_super_class_parts = app_cls_name.split(".")
    files = os.listdir(decompiled_dir)
    found_smali_file = None
    for f in files:
        smali_file = os.path.join(decompiled_dir, f, *most_super_class_parts) + ".smali"
        if os.path.isfile(smali_file):
            found_smali_file = smali_file
            break
    return found_smali_file


sys.setrecursionlimit(5000)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('infile', help='Input APK,DEX name')
    parser.add_argument('-o', '--out', nargs='?', help='Output APK file name')
    parser.add_argument('--sign', action='store_true', default=False, help='Sign apk')
    parser.add_argument('--filter', default='filter.txt', help='Method filter configure file')
    parser.add_argument('--no-build', action='store_true', default=False, help='Do not build the compiled code')
    parser.add_argument('--source-dir', help='The compiled cpp code output directory.')
    parser.add_argument('--project-archive', default='project-source-' + time_str + '.zip',
                        help='Archive the project directory')

    args = vars(parser.parse_args())
    infile = args['infile']
    outapk = args['out']
    do_sign = args['sign']
    filtercfg = args['filter']
    do_compile = not args['no_build']
    source_archive = args['project_archive']

    if args['source_dir']:
        project_dir = args['source_dir']
    else:
        project_dir = None

    dcc_cfg = {}

    script_directory = os.path.split(os.path.abspath(__file__))[0]
    abs_filename = os.path.join(script_directory, "dcc.cfg")

    with open(abs_filename) as fp:
        dcc_cfg = json.load(fp)

    if 'ndk_dir' in dcc_cfg and os.path.exists(dcc_cfg['ndk_dir']):
        ndk_dir = dcc_cfg['ndk_dir']
        if is_windows():
            NDK_BUILD = os.path.join(ndk_dir, 'ndk-build.cmd')
        else:
            NDK_BUILD = os.path.join(ndk_dir, 'ndk-build')

    if 'apktool' in dcc_cfg and os.path.exists(dcc_cfg['apktool']):
        APKTOOL = dcc_cfg['apktool']

    try:
        dcc_main(infile, filtercfg, outapk, do_compile, project_dir, source_archive)
    except Exception as e:
        logger.error("Compile %s failed!" % infile, exc_info=True)
    finally:
        pass
        # clean_temp_files()
