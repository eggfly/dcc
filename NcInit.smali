.class public Lkvm/NcInit;
.super Ljava/lang/Object;
.source "NcInit.java"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 8
    :try_start_0
    const-string v0, "nc"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    goto :goto_0

    .line 9
    :catch_0
    move-exception v0

    .line 10
    .local v0, "e":Ljava/lang/UnsatisfiedLinkError;
    invoke-virtual {v0}, Ljava/lang/UnsatisfiedLinkError;->printStackTrace()V

    .line 12
    .end local v0    # "e":Ljava/lang/UnsatisfiedLinkError;
    :goto_0
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static setup()V
    .locals 2

    .line 15
    const-string v0, "NcInit"

    const-string v1, "NcInit"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 16
    return-void
.end method
