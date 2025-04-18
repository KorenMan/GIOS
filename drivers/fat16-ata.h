#pragma once

#include "fat16.h"
#include "../lib/types.h"

void fat16_ata_init_subsystem();
int fat16_mount_ata(fat16_filesystem_t *fs, int bus, int drive, int partition_index);
int fat16_unmount_ata(fat16_filesystem_t *fs);
int fat16_format_partition(int bus, int drive, int partition_index);
int fat16_list_partitions(int bus, int drive);
int fat16_create_partition(int bus, int drive, int partition_index, u32_t start_sector, u32_t total_sectors);
int fat16_ata_example();
