#!/bin/sh
#
# OSGi bundling step called by add_module.sh (sh ./bnd.sh <jar>).
#
# BC's release bnd.sh is not part of the source distribution. The published
# jars were wrapped with bnd 2.2.0 (manifest "Tool: Bnd-2.2.0.20130927-173453"),
# so wrap the Ant-built jar in place with the same bnd release from Maven
# Central to add the Bundle-*, Export-Package and Import-Package headers. The
# Ant manifest attributes (Implementation-*, Automatic-Module-Name, ...) are
# kept by bnd.
#
set -e

if [ $# -ne 1 ]
then
    echo "usage: bnd.sh <jar>"
    exit 1
fi

jar="$1"

BND_VERSION=2.2.0
BND_JAR="${BND_JAR:-${HOME}/.bnd/bnd-${BND_VERSION}.jar}"
if [ ! -f "$BND_JAR" ]
then
    mkdir -p `dirname "$BND_JAR"`
    curl -fsSL -o "$BND_JAR" "https://repo.maven.apache.org/maven2/biz/aQute/bnd/bnd/${BND_VERSION}/bnd-${BND_VERSION}.jar"
fi

# bcpkix-jdk15on-168.jar -> bcpkix
bsn=`basename "$jar" | sed -e 's/-jdk15on.*$//'`
# release.name: 1.68
version=`grep '^release.name' bc-build.properties | sed -e 's/^release.name:[ ]*//'`

work=`mktemp -d`
cat > "$work/bundle.bnd" <<EOF
Bundle-SymbolicName: $bsn
Bundle-Name: $bsn
Bundle-Version: $version
Bundle-RequiredExecutionEnvironment: J2SE-1.5
Export-Package: org.bouncycastle.*;version=$version;-noimport:=true
Import-Package: org.bouncycastle.*;version=$version,*;resolution:=optional
EOF

java -jar "$BND_JAR" wrap -p "$work/bundle.bnd" -o "$work/out.jar" "$jar"
cp "$work/out.jar" "$jar"
rm -rf "$work"

echo "bnd: wrapped $jar as OSGi bundle $bsn $version"
