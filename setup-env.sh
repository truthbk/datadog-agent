#!/bin/bash

CI_PROJECT_DIR=$(pwd)/env-setup

#mkdir $CI_PROJECT_DIR

EC2_X86_INSTANCE_TYPE="i3.metal"
EC2_ARM_INSTANCE_TYPE="m6g.metal"
X86_AMI_ID="ami-0584a00dd384af6ab"
ARM_AMI_ID="ami-0a5c054df5931fbfc"
AWS_REGION=us-east-1
STACK_DIR=$CI_PROJECT_DIR/stack.dir
# The ssh key is created by the pulumi scenario, to be used for creating
# instances in the build-stable account. We reuse this file to ssh into
# the instances in subsequent jobs.
AWS_SSH_KEY=$CI_PROJECT_DIR/ssh_key

export CI_PROJECT_DIR=$CI_PROJECT_DIR
export LibvirtSSHKeyX86=$CI_PROJECT_DIR/libvirt_rsa-x86
export LibvirtSSHKeyARM=$CI_PROJECT_DIR/libvirt_rsa-arm
export E2E_API_KEY=00000000000000000000000000000000
export PULUMI_CONFIG_PASSPHRASE=1234
aws-vault exec sandbox-account-admin -- inv -e system-probe.test-microvms --instance-type-x86=$EC2_X86_INSTANCE_TYPE --instance-type-arm=$EC2_ARM_INSTANCE_TYPE --x86-ami-id=$X86_AMI_ID --arm-ami-id=$ARM_AMI_ID

cat $CI_PROJECT_DIR/stack.outputs


