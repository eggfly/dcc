.class public Lkvm/MyApp;
.super Landroid/app/Application;
.source "MyApp.java"


# direct methods
.method static constructor <clinit>()V
    .locals 2
    const-string v0, "MyApp"

    const-string v1, "MyApp.<clinit>()"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    invoke-static {}, Lkvm/NcInit;->setup()V

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 5
    invoke-direct {p0}, Landroid/app/Application;-><init>()V

    return-void
.end method
