#!/bin/bash

echo ""
echo "+++++++++++++++++ build updater package start +++++++++++++++++++++++"
SOURCE_ROOT_DIR=$1
PRODUCT_NAME=$2
export PATH=/usr/bin:$PATH
PIP_PATH=$(command -v pip)
PYTHON_PATH=$(command -v python)
UPDATER_CONFIG_SRC=${SOURCE_ROOT_DIR}/base/update/packaging_tools/openvalley/sources_package/images/updater_config
UPDATER_DIFF_CONFIG_SRC=${SOURCE_ROOT_DIR}/base/update/packaging_tools/openvalley/target_package/updater_config
UPDATER_BINARY_SRC=${SOURCE_ROOT_DIR}/out/${PRODUCT_NAME}/packages/phone/updater/bin/updater_binary
BUILD_UPDATE_PY_SRC=${SOURCE_ROOT_DIR}/base/update/packaging_tools/build_update.py
PEM_SRC=${SOURCE_ROOT_DIR}/base/update/packaging_tools/openvalley/rsa_private_key2048.pem
# OUT_DIR=${SOURCE_ROOT_DIR}/out/${PRODUCT_NAME}/packages/phone/images
OUT_DIR=${SOURCE_ROOT_DIR}/base/update/packaging_tools/openvalley/target_package/images
UPDATER_BASE_SRC=${SOURCE_ROOT_DIR}/base/update/packaging_tools/openvalley/sources_package/images
UPDATER_BASE_PARTITION_XML=${SOURCE_ROOT_DIR}/base/update/packaging_tools/openvalley/target_package/updater_config/partition_file.xml

function install_xmltodict() {
    ${PYTHON_PATH} -c "import xmltodict" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Installing xmltodict library ..."
        ${PIP_PATH} install xmltodict
    fi
}

function make_updater_full_package() {
    ${PYTHON_PATH} ${BUILD_UPDATE_PY_SRC} ${OUT_DIR} ${OUT_DIR} -pk ${PEM_SRC}
}

function make_updater_full_stream_package() {
    ${PYTHON_PATH} ${BUILD_UPDATE_PY_SRC} ${OUT_DIR} ${OUT_DIR} -pk ${PEM_SRC} -su
}

function make_updater_sd_package() {
    
    ${PYTHON_PATH} ${BUILD_UPDATE_PY_SRC} ${OUT_DIR} ${OUT_DIR} -pk ${PEM_SRC} -sc
    
}
function make_updater_diff_package() {
    
    ${PYTHON_PATH} ${BUILD_UPDATE_PY_SRC} ${OUT_DIR} ${OUT_DIR} -pk ${PEM_SRC} -s $UPDATER_BASE_SRC
    
}

function make_updater_partitioned_package {
    
    ${PYTHON_PATH} ${BUILD_UPDATE_PY_SRC} ${OUT_DIR} ${OUT_DIR} -pk ${PEM_SRC} -pf $UPDATER_BASE_PARTITION_XML

}

function make_updater_diff_stream_package {

    ${PYTHON_PATH} ${BUILD_UPDATE_PY_SRC} ${OUT_DIR} ${OUT_DIR} -pk ${PEM_SRC} -s $UPDATER_BASE_SRC -su -ab

}


function  cp_source_to_target()
{
    cp -r ${UPDATER_CONFIG_SRC} ${OUT_DIR}
    cp -r ${UPDATER_BINARY_SRC} ${OUT_DIR}
}

function cp_diff_config_to_target()
{
    cp -r ${UPDATER_DIFF_CONFIG_SRC} ${OUT_DIR}
    cp -r ${UPDATER_BINARY_SRC} ${OUT_DIR}
}

function cp_partition_config_to_target()
{
    cp -r ${UPDATER_DIFF_CONFIG_SRC} ${OUT_DIR}
    cp -r ${UPDATER_BINARY_SRC} ${OUT_DIR}
    
}

function  rm_full_config()
{
    rm -rf ${OUT_DIR}/updater_config
    rm -rf ${OUT_DIR}/vendor.map
    rm ${UPDATER_BASE_SRC}/build_tools.zip
    rm ${UPDATER_BASE_SRC}/board_list
    rm ${UPDATER_BASE_SRC}/version_list
    rm ${UPDATER_BASE_SRC}/all_max_stash
    rm ${UPDATER_BASE_SRC}/vendor.new.dat
    rm ${UPDATER_BASE_SRC}/vendor.patch.dat
    rm ${UPDATER_BASE_SRC}/vendor.transfer.list
    rm ${UPDATER_BASE_SRC}/vendor.map
    rm ${UPDATER_BASE_SRC}/system.map
    rm -rf ${UPDATER_BASE_SRC}/diff_list
}

# function  rm_copy_source()
# {
#     rm -rf ${OUT_DIR}/updater_config
#     rm -rf ${OUT_DIR}/updater_binary
# }

function  rm_all_source()
{
    # 先把生成的结果copy一下到sources_package
    cp ${OUT_DIR}/updater_diff.zip ${UPDATER_BASE_SRC}/
    unzip -d ${UPDATER_BASE_SRC}/diff_list ${UPDATER_BASE_SRC}/updater_diff.zip
    unzip -d ${UPDATER_BASE_SRC}/diff_list/build_tools ${UPDATER_BASE_SRC}/diff_list/build_tools.zip
    rm -rf ${OUT_DIR}/updater_config
    rm ${OUT_DIR}/updater_diff.zip
    # rm ${OUT_DIR}/build_tools.zip
    # rm ${OUT_DIR}/board_list
    # rm ${OUT_DIR}/version_list
    # rm ${OUT_DIR}/all_max_stash
    # rm ${OUT_DIR}/vendor.new.dat
    # rm ${OUT_DIR}/vendor.patch.dat
    # rm ${OUT_DIR}/vendor.transfer.list
    rm ${OUT_DIR}/vendor.map
    rm ${OUT_DIR}/system.map
    # cp -r ${SOURCE_ROOT_DIR}/out/${PRODUCT_NAME}/clang_x64/updater/updater/diff ${PACKAGING_TOOLS_PATH}/lib
    # cp -r ${SOURCE_ROOT_DIR}/out/${PRODUCT_NAME}/clang_x64/thirdparty/e2fsprogs/* ${PACKAGING_TOOLS_PATH}/lib
}


start_time=$(date +%s%N)  # Get start time in nanoseconds

install_xmltodict
cp_source_to_target
# make_updater_full_package
# make_updater_sd_package
# make_updater_full_stream_package
rm_full_config

cp_diff_config_to_target
make_updater_diff_package
# make_updater_diff_stream_package

# cp_partition_config_to_target
# make_updater_partitioned_package
rm_all_source
rm_full_config

end_time=$(date +%s%N)  # Get end time in nanoseconds
elapsed_time=$(( (end_time - start_time) / 1000000000))  # Convert nanoseconds to milliseconds
echo "Cost time: $elapsed_time seconds"
echo "+++++++++++++++++ build updater package finish +++++++++++++++++++++++"