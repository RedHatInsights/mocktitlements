#!/bin/bash

set +x

IMAGE="quay.io/cloudservices/mocktitlements"

function push_image_to_quay() {
    local CICD_URL=https://raw.githubusercontent.com/RedHatInsights/bonfire/master/cicd
    curl -s $CICD_URL/bootstrap.sh > .cicd_bootstrap.sh && source .cicd_bootstrap.sh

    source $CICD_ROOT/build.sh
}

echo "Building..."

go build

echo "Built!"

export APP_ROOT=$(pwd)
export WORKSPACE=${WORKSPACE:-$APP_ROOT} # if running in jenkins, use the build's workspace

push_image_to_quay

mkdir -p $WORKSPACE/artifacts
cat << EOF > $WORKSPACE/artifacts/junit-dummy.xml
<testsuite tests="1">
    <testcase classname="dummy" name="dummytest"/>
</testsuite>
EOF