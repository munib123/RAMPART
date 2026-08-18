# CrossVul Fix Pair: Improper Access Control in shell
**Pair ID:** 4908_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4908_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```bash
Lines 27-67 of the vulnerable file.

        ;;
    esac

    echo $plat_abi
}

gobuild() {
    arch=$1

    plat_abi=$(get_platform_abi $arch)

    if [ $arch = "386" ]; then
        output_dir="bin/i686-linux-gnu"
    else
        output_dir="bin/$plat_abi"
    fi

    mkdir -p $output_dir
    cd $output_dir
    GOARCH=$arch GOARM=7 CGO_ENABLED=1 CC=${plat_abi}-gcc go build -ldflags "-extld=${plat_abi}-gcc" github.com/snapcore/snapweb/cmd/snapweb
    cd - > /dev/null
}

echo "Building web assets with gulp..."
gulp

orig_pwd="$(pwd)"

top_builddir="$(mktemp -d)"
trap 'rm -rf "$top_builddir"' EXIT

echo Obtaining go dependencies
go get launchpad.net/godeps
godeps -u dependencies.tsv

# build one snap per arch
for ARCH in amd64 arm64 armhf i386; do
    builddir="${top_builddir}/${ARCH}"
    mkdir -p "$builddir"

    cp -r pkg/. ${builddir}/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,7 @@
     mkdir -p $output_dir
     cd $output_dir
     GOARCH=$arch GOARM=7 CGO_ENABLED=1 CC=${plat_abi}-gcc go build -ldflags "-extld=${plat_abi}-gcc" github.com/snapcore/snapweb/cmd/snapweb
+    GOARCH=$arch GOARM=7 CGO_ENABLED=1 CC=${plat_abi}-gcc go build -o generate-token -ldflags "-extld=${plat_abi}-gcc" $srcdir/cmd/generate-token/main.go
     cd - > /dev/null
 }
 
@@ -60,10 +61,12 @@
 godeps -u dependencies.tsv
 
 # build one snap per arch
+# for ARCH in amd64 ; do
 for ARCH in amd64 arm64 armhf i386; do
     builddir="${top_builddir}/${ARCH}"
     mkdir -p "$builddir"
 
+    srcdir=`pwd`
     cp -r pkg/. ${builddir}/
     mkdir $builddir/www
     cp -r www/public www/templates $builddir/www
```
