.class public Lkvm/NcInit;
.super Ljava/lang/Object;
.source "NcInit.java"


# static fields
.field private static final TAG:Ljava/lang/String; = "NcInit"


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 9
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    .line 11
    .local v0, "start":J
    :try_start_0
    const-string v2, "nc"

    invoke-static {v2}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 13
    const-string v2, "NcInit"

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "NcInit.<clinit>() costs "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v4

    sub-long v6, v4, v0

    invoke-virtual {v3, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v4, " ms"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v2, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    goto :goto_0

    .line 14
    :catch_0
    move-exception v2

    .line 15
    .local v2, "e":Ljava/lang/UnsatisfiedLinkError;
    invoke-virtual {v2}, Ljava/lang/UnsatisfiedLinkError;->printStackTrace()V

    .line 17
    .end local v0    # "start":J
    .end local v2    # "e":Ljava/lang/UnsatisfiedLinkError;
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

    .line 20
    const-string v0, "NcInit"

    const-string v1, "NcInit"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 21
    return-void
.end method
