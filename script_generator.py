#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Description : Create script file for updater
"""

import os
import re
import tempfile
from decimal import getcontext
from decimal import Decimal

from log_exception import VendorExpandError
from log_exception import UPDATE_LOGGER
from utils import OPTIONS_MANAGER
from utils import PARTITION_FILE
from utils import TOTAL_SCRIPT_FILE_NAME
from utils import SCRIPT_FILE_NAME
from utils import SCRIPT_KEY_LIST
from utils import UPDATE_BIN_FILE_NAME


class Script:

    def __init__(self):
        self.script = []
        self.version = 0
        self.info = {}

    def add_command(self, cmd=None):
        """
        Add command content to the script.
        :param cmd: command content
        :return:
        """
        self.script.append(cmd)

    def get_script(self):
        """
        Get the script list.
        :return: script list
        """
        return self.script

    def sha_check(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'sha_check')

    def image_sha_check(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'image_sha_check')

    def first_block_check(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'first_block_check')

    def image_patch(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'image_patch')

    def abort(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'abort')

    def show_progress(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'show_progress')

    def block_update(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'block_update')

    def raw_image_write(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'raw_image_write')

    def get_status(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'get_status')

    def set_status(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'set_status')

    def reboot_now(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'reboot_now')

    def updater_partitions(self, *args, **kwargs):
        raise VendorExpandError(type(self), 'updater_partitions')


class PreludeScript(Script):
    def __init__(self):
        super().__init__()


class VerseScript(Script):
    def __init__(self):
        super().__init__()

    def sha_check(self, ranges_str, expected_sha, partition):
        """
        Get the sha_check command.
        :param ranges_str: ranges string
        :param expected_sha: hash value
        :param partition: image name
        :return:
        """
        cmd = ('sha_check("/{partition}", "{ranges_str}", '
               '"{expected_sha}")').format(
            ranges_str=ranges_str,
            expected_sha=expected_sha, partition=partition)
        return cmd

    def image_sha_check(self, partition, src_size, src_hash,
        dst_size, dst_hash):
        """
        Get the image_sha_check command.
        :param ranges_str: ranges string
        :param expected_sha: hash value
        :param partition: image name
        :return:
        """
        cmd = ('image_sha_check("/{partition}", '
                '"{src_size}", "{src_hash}", '
                '"{dst_size}", "{dst_hash}")').format(
                partition=partition, src_size=src_size, src_hash=src_hash,
                dst_size=dst_size, dst_hash=dst_hash)
        return cmd

    def first_block_check(self, partition):
        """
        Get the first_block_check command.
        :param partition: image name
        :return:
        """
        cmd = 'first_block_check("/{partition}")'.format(
            partition=partition)
        return cmd

    def abort(self, partition):
        """
        Get the abort command.
        :param partition: image name
        :return:
        """
        cmd = 'abort("ERROR: {partition} partition ' \
              'fails to incremental check!");\n'.format(
                partition=partition)
        return cmd

    def show_progress(self, start_progress, dur):
        """
        Get the show_progress command.
        'dur' may be zero to advance the progress via SetProgress
        :param start_progress: start progress
        :param dur: seconds
        :return:
        """
        cmd = 'show_progress({start_progress}, {dur});\n'.format(
            start_progress=float(start_progress), dur=float(dur))
        return cmd

    def image_patch(self, partition, src_size, src_hash, target_size, target_hash):
        """
        Get the image_patch command.
        :param partition:  image name
        :return:
        """
        cmd = 'image_patch("/{partition}", "{src_size}", ' \
              '"{src_hash}", "{target_size}", "{target_hash}", ' \
              '"{partition}.patch.dat");\n'.format(partition=partition, src_size=src_size,
              src_hash=src_hash, target_size=target_size, target_hash=target_hash)
        return cmd

    def block_update(self, partition):
        """
        Get the block_update command.
        :param partition:  image name
        :return:
        """
        cmd = 'block_update("/{partition}", ' \
              '"{partition}.transfer.list", "{partition}.new.dat", ' \
              '"{partition}.patch.dat");\n'.format(partition=partition)
        return cmd

    def image_write(self, partition, image_name, image_path):
        return self.raw_image_write(partition, image_name)

    def raw_image_write(self, partition, image_name):
        """
        Get the raw_image_write command.
        :param partition:  image name
        :return:
        """
        cmd = 'raw_image_write("/%s", "/%s");\n' % (partition, image_name)
        return cmd

    def get_status(self):
        """
        Get the get_status command.
        :return:
        """
        cmd = 'get_status("/misc")'
        return cmd

    def set_status(self, status_value):
        """
        Get the set_status command.
        :param status_value: status value to be set
        :return:
        """
        cmd = 'set_status("/misc", %s);\n' % status_value
        return cmd

    def reboot_now(self):
        """
        Get the reboot_now command.
        :return:
        """
        cmd = 'reboot_now();\n'
        return cmd

    def updater_partitions(self):
        """
        Get the updater_partitions command.
        :return:
        """
        cmd = 'update_partitions("/%s");\n' % PARTITION_FILE
        return cmd

    def full_image_update(self, update_file_name):
        cmd = 'update_from_bin("%s");\n' % update_file_name
        return cmd

    def pkg_extract(self, pkg_file_name, dest_path):
        cmd = 'pkg_extract("%s", "%s");\n' % (pkg_file_name, dest_path)
        return cmd


class RefrainScript(Script):
    def __init__(self):
        super().__init__()


class EndingScript(Script):
    def __init__(self):
        super().__init__()


def write_script(script_content, opera_name):
    """
    Generate the {opera}script.
    :param script_content: script content
    :param opera_name: Opera phase names corresponding to the script content
                    'prelude', 'verse', 'refrain', and 'ending'.
    :return:
    """
    script_file = tempfile.NamedTemporaryFile(mode='w+')
    script_file.write(script_content)
    script_file.seek(0)
    script_file_name = ''.join([opera_name.title(), SCRIPT_FILE_NAME])
    OPTIONS_MANAGER.opera_script_file_name_dict[opera_name].\
        append((script_file_name, script_file))
    UPDATE_LOGGER.print_log("%s generation complete!" % script_file_name)


def generate_total_script():
    """
    Generate the overall script.
    """
    content_list = []
    for each_key, each_value in \
            OPTIONS_MANAGER.opera_script_file_name_dict.items():
        for each in each_value:
            each_content = "LoadScript(\"%s\", %s);" % \
                           (each[0], SCRIPT_KEY_LIST.index(each_key))
            content_list.append(each_content)
    script_total = tempfile.NamedTemporaryFile(mode='w+')
    script_total.write('\n'.join(content_list))
    script_total.seek(0)
    OPTIONS_MANAGER.total_script_file_obj = script_total
    UPDATE_LOGGER.print_log("%s generation complete!" % TOTAL_SCRIPT_FILE_NAME)


def get_progress_value(distributable_value=100):
    """
    Allocate a progress value to each image update.
    :param distributable_value: distributable value
    :return:
    """
    progress_value_dict = {}
    full_img_list = OPTIONS_MANAGER.full_img_list
    incremental_img_list = OPTIONS_MANAGER.incremental_img_list
    file_size_list = []
    each_img_size = 0
    if len(full_img_list) == 0 and len(incremental_img_list) == 0:
        UPDATE_LOGGER.print_log(
            "get progress value failed! > getting progress value failed!",
            UPDATE_LOGGER.ERROR_LOG)
        return False
    for partition in incremental_img_list:
        # Obtain the size of the incremental image file.
        if partition in OPTIONS_MANAGER.incremental_image_file_obj_dict:
            file_obj = OPTIONS_MANAGER.incremental_image_file_obj_dict[partition]
            each_img_size = os.path.getsize(file_obj.name)
        elif partition in OPTIONS_MANAGER.incremental_block_file_obj_dict:
            new_dat_file_obj, patch_dat_file_obj, transfer_list_file_obj =\
                OPTIONS_MANAGER.incremental_block_file_obj_dict[partition].get_file_obj()
            each_img_size = os.path.getsize(new_dat_file_obj.name) + os.path.getsize(patch_dat_file_obj.name)
        file_size_list.append(each_img_size)

    total_full_img_size = 0
    for idx, _ in enumerate(full_img_list):
        # Obtain the size of the full image file.
        file_obj = OPTIONS_MANAGER.full_image_file_obj_list[idx]
        total_full_img_size += os.path.getsize(file_obj.name)
    file_size_list.append(total_full_img_size)

    proportion_value_list = get_proportion_value_list(
        file_size_list, distributable_value=distributable_value)

    adjusted_proportion_value_list = adjust_proportion_value_list(
        proportion_value_list, distributable_value)

    all_img_list = incremental_img_list + [UPDATE_BIN_FILE_NAME]
    current_progress = 40
    for idx, each_img in enumerate(all_img_list):
        temp_progress = current_progress + adjusted_proportion_value_list[idx]
        progress_value_dict[each_img] = (current_progress, temp_progress)
        current_progress = temp_progress
    return progress_value_dict


def get_proportion_value_list(file_size_list, distributable_value=100):
    """
    Obtain the calculated progress proportion value list
    (proportion_value_list).
    :param file_size_list: file size list
    :param distributable_value: distributable value
    :return proportion_value_list: progress proportion value list
    """
    sum_size = sum(file_size_list)
    getcontext().prec = 2
    proportion_value_list = []
    for each_size_value in file_size_list:
        proportion = Decimal(str(float(each_size_value))) / Decimal(
            str(float(sum_size)))
        proportion_value = int(
            Decimal(str(proportion)) *
            Decimal(str(float(distributable_value))))
        if proportion_value == 0:
            proportion_value = 1
        proportion_value_list.append(proportion_value)
    return proportion_value_list


def adjust_proportion_value_list(proportion_value_list, distributable_value):
    """
    Adjust the calculated progress proportion value list to ensure that
    sum is equal to distributable_value.
    :param proportion_value_list: calculated progress proportion value list
    :param distributable_value: number of distributable progress values
    :return proportion_value_list: new progress proportion value list
    """
    if len(proportion_value_list) == 0:
        return []
    sum_proportion_value = sum(proportion_value_list)
    if sum_proportion_value > distributable_value:
        max_value = max(proportion_value_list)
        max_idx = proportion_value_list.index(max_value)
        proportion_value_list[max_idx] = \
            max_value - (sum_proportion_value - distributable_value)
    elif sum_proportion_value < distributable_value:
        min_value = min(proportion_value_list)
        min_idx = proportion_value_list.index(min_value)
        proportion_value_list[min_idx] = \
            min_value + (distributable_value - sum_proportion_value)
    return proportion_value_list


def create_script(prelude_script, verse_script,
                  refrain_script, ending_script):
    """
    Generate the script file.
    :param prelude_script: prelude script
    :param verse_script: verse script
    :param refrain_script: refrain script
    :param ending_script: ending script
    :return:
    """
    # Generate the prelude script.
    prelude_script.add_command("\n# ---- prelude ----\n")

    # Get the distribution progress.
    progress_value_dict = get_progress_value()
    if progress_value_dict is False:
        return False
    verse_script_content_list = verse_script.get_script()
    updater_content = []
    verse_script_content = '\n'.join(verse_script_content_list)

    for key, value in progress_value_dict.items():
        show_progress_content = \
            verse_script.show_progress((value[1] - value[0]) / 100, 0)
        verse_script_content = \
            re.sub(r'%s_WRITE_FLAG' % key, '%s' % show_progress_content,
                   verse_script_content, count=1)
    # Generate the verse script.
    write_script(verse_script_content, 'verse')
    # Generate the refrain script.
    refrain_script.add_command("\n# ---- refrain ----\n")
    # Generate the ending script.
    ending_script.add_command("\n# ---- ending ----\n")

    generate_total_script()
