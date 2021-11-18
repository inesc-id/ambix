#include "ambix.h"

long long free_space_node(int node, long long *sz)
{
    long long node_fr = 0;
    *sz = numa_node_size64(node, &node_fr);
    return node_fr;
}

long long free_space_tot_bytes(int mode, long long *sz)
{

    long long total_node_sz = 0;
    long long total_node_fr = 0;

    if (mode == DRAM_MODE) {
        for (int i=0; i < n_dram_nodes; i++) {
            long long node_sz = 0;
            total_node_fr += free_space_node(DRAM_NODES[i], &node_sz);
            total_node_sz += node_sz;
        }
    }
    else {
        for (int i=0; i < n_nvram_nodes; i++) {
            long long node_sz = 0;
            total_node_fr += free_space_node(NVRAM_NODES[i], &node_sz);
            total_node_sz += node_sz;
        }
    }

    *sz = total_node_sz;
    return total_node_fr;
}

u32 free_space_tot_per(int mode, long long *sz)
{
    long long fr = free_space_tot_bytes(mode, sz);
    return (*sz - fr) * 100 / *sz;
}

int do_migration(int mode, int n_found)
{
    void **addr = malloc(sizeof(unsigned long) * n_found);
    int *dest_nodes = malloc(sizeof(int) * n_found);
    int *status = malloc(sizeof(int) * n_found);

    const int *node_list;
    int n_nodes;

    if (mode == DRAM_MODE) {
        node_list = NVRAM_NODES;
        n_nodes = n_nvram_nodes;
    }
    else {
        node_list = DRAM_NODES;
        n_nodes = n_dram_nodes;
    }

    for (int i=0; i< n_found; i++) {
        status[i] = -123;
    }

    int n_processed = 0;
    for (int i=0; (i < n_nodes) && (n_processed < n_found); i++) {
        int curr_node = node_list[i];

        int n_avail_pages = free_space_pages(curr_node);

        int j=0;
        for (; (j < n_avail_pages) && (n_processed+j < n_found); j++) {
            addr[n_processed+j] = (void *) candidates[n_processed+j].addr;
            dest_nodes[n_processed+j] = curr_node;
        }

        n_processed += j;
    }
    int n_migrated, i;
    int e = 0; // counts failed migrations

    for (n_migrated=0, i=0; n_migrated < n_processed; n_migrated+=i) {
        int curr_pid;
        curr_pid=candidates[n_migrated].pid_retval;

        for (i=1; (candidates[n_migrated+i].pid_retval == curr_pid) && (n_migrated+i < n_processed); i++);

        void **addr_displacement = addr + n_migrated;
        int *dest_nodes_displacement = dest_nodes + n_migrated;
        if (move_pages(curr_pid, (unsigned long) i, addr_displacement, dest_nodes_displacement, status, 0)) {
            // Migrate all and output addresses that could not migrate
            for (int j=0; j < i; j++) {
                if (move_pages(curr_pid, 1, addr_displacement + j, dest_nodes_displacement + j, status, 0)) {
                    printf("Error migrating addr: %ld, pid: %d\n", (unsigned long) *(addr_displacement + j), curr_pid);
                    e++;
                }
            }
        }
    }

    free(addr);
    free(dest_nodes);
    free(status);
    return n_migrated - e;
}

int do_switch(int n_found)
{
    void **addr_dram = malloc(sizeof(unsigned long) * n_found);
    int *dest_nodes_dram = malloc(sizeof(int) * n_found);
    void **addr_nvram = malloc(sizeof(unsigned long) * n_found);
    int *dest_nodes_nvram = malloc(sizeof(int) * n_found);
    int *status = malloc(sizeof(int) * n_found);

    for (int i=0; i < n_found; i++) {
        status[i] = -123;
    }

    int dram_migrated = 0;
    int nvram_migrated = 0;
    int dram_e = 0; // counts failed migrations
    int nvram_e = 0; // counts failed migrations

    int dram_free = 1;
    int nvram_free = 1;

    while ((((dram_migrated + dram_e) < n_found) || ((nvram_migrated + nvram_e) < n_found)) && (dram_free || nvram_free)) {
        // DRAM -> NVRAM
        int old_n_processed = dram_migrated + dram_e;
        int dram_processed = old_n_processed;

        for (int i=0; (i < n_nvram_nodes) && (dram_processed < n_found); i++) {
            int curr_node = NVRAM_NODES[i];

            long long node_fr = 0;
            numa_node_size64(curr_node, &node_fr);
            int n_avail_pages = node_fr / page_size;

            int j=0;
            for (; (j < n_avail_pages) && (j+dram_processed < n_found); j++) {
                addr_dram[dram_processed+j] = (void *) candidates[n_found+1+j].addr;
                dest_nodes_nvram[dram_processed+j] = curr_node;
            }

            dram_processed += j;
        }
        if (old_n_processed < dram_processed) {
            // Send processed pages to NVRAM
            int n_migrated, i;
            dram_free = 1;

            for (n_migrated=0, i=0; n_migrated < dram_processed; n_migrated+=i) {
                int curr_pid;
                curr_pid = candidates[n_found+1+n_migrated].pid_retval;

                for (i=1; (candidates[n_found+1+n_migrated+i].pid_retval == curr_pid) && (n_migrated+i < dram_processed); i++);
                void **addr_displacement = addr_dram + n_migrated;
                int *dest_nodes_displacement = dest_nodes_nvram + n_migrated;
                if (numa_move_pages(curr_pid, (unsigned long) i, addr_displacement, dest_nodes_displacement, status, 0)) {
                    // Migrate all and output addresses that could not migrate
                    for (int j=0; j < i; j++) {
                        if (numa_move_pages(curr_pid, 1, addr_displacement + j, dest_nodes_displacement + j, status, 0)) {
                            printf("Error migrating DRAM/MEM addr: %ld, pid: %d\n", (unsigned long) *(addr_displacement + j), curr_pid);
                            dram_e++;
                        }
                    }
                }
            }
        }
        else {
            dram_free = 0;
        }

        dram_migrated = dram_processed - dram_e;

        // NVRAM -> DRAM
        old_n_processed = nvram_migrated + nvram_e;
        int nvram_processed = old_n_processed;

        for (int i=0; (i < n_dram_nodes) && (nvram_processed < n_found); i++) {
            int curr_node = DRAM_NODES[i];

            long long node_fr = 0;
            numa_node_size64(curr_node, &node_fr);
            int n_avail_pages = node_fr / page_size;

            int j=0;
            for (; (j < n_avail_pages) && (j+nvram_processed < n_found); j++) {
                addr_nvram[nvram_processed+j] = (void *) candidates[nvram_processed+j].addr;
                dest_nodes_dram[nvram_processed+j] = curr_node;
            }

            nvram_processed += j;
        }

        if (old_n_processed < nvram_processed) {
            // Send processed pages to DRAM
            int n_migrated, i;
            nvram_free = 1;

            for (n_migrated=0, i=0; n_migrated < nvram_processed; n_migrated+=i) {
                int curr_pid;
                curr_pid=candidates[n_migrated].pid_retval;

                for (i=1; (candidates[n_migrated+i].pid_retval == curr_pid) && (n_migrated+i < nvram_processed); i++);
                void **addr_displacement = addr_nvram + n_migrated;
                int *dest_nodes_displacement = dest_nodes_dram + n_migrated;
                if (numa_move_pages(curr_pid, (unsigned long) i, addr_displacement, dest_nodes_displacement, status, 0)) {
                    // Migrate all and output addresses that could not migrate
                    for (int j=0; j < i; j++) {
                        if (numa_move_pages(curr_pid, 1, addr_displacement + j, dest_nodes_displacement + j, status, 0)) {
                            printf("Error migrating NVRAM addr: %ld, pid: %d\n", (unsigned long) *(addr_displacement + j), curr_pid);
                            nvram_e++;
                        }
                    }
                }
            }
        }
        else {
            nvram_free = 0;
        }

        nvram_migrated = nvram_processed - nvram_e;
    }

    free(addr_dram);
    free(addr_nvram);
    free(dest_nodes_dram);
    free(dest_nodes_nvram);
    free(status);

    return dram_migrated + nvram_migrated;
}


int migrate_pages(int n_pages, int mode)
{
    int n_found = ambix_find(m_pages, mode);
    if (n_found < 0) {
        return 0;
    }
    switch (mode) {
    case DRAM_MODE:
        return do_migration(DRAM_MODE, n_found);
    case NVRAM_MODE:
    case NVRAM_INTENSIVE_MODE:
    case NVRAM_WRITE_MODE:
        return do_migration(NVRAM_MODE, n_found);
    case SWITCH_MODE:
        return do_switch(n_found);
    }
}

void *memcheck_placement(void *args)
{
    long long dram_sz = 0;
    long long nvram_sz = 0;
    u32 dram_usage;
    u32 nvram_usage;
    int n_pages;
    time_t prev_memdata_lmod = 0;

    int n_migrated = 0;
    int switch_migrated = 0;
    int thresh_migrated = 0;
    int sleep_interval = memcheck_interval;

    if (thresh_act || switch_act) {
        dram_usage = free_space_tot_per(DRAM_MODE, &dram_sz);
        nvram_usage = free_space_tot_per(NVRAM_MODE, &nvram_sz);
        printf("Current DRAM Usage: %0.2f%%\n", dram_usage);
        printf("Current NVRAM Usage: %0.2f%%\n", nvram_usage);
    }

    if (switch_act) {
        time_t memdata_lmod = get_memdata_mtime();
        if (memdata_lmod == 0 || (memdata_lmod == prev_memdata_lmod)) {
            printf("MEMCHECK: Old or invalid memdata values. Ignoring...\n");
        }
        else {
            prev_memdata_lmod = memdata_lmod;
            // -- memdata_t *md = read_memdata();
            if (!check_memdata(md)) {
                printf("MEMCHECK: Unexpected memdata values.\n");
            }
            else {
                u64 pmm_bw;
                if (PMM_MIXED) {
                    // -- FIXME pmm_bw = md->sys_pmmAppBW;
                }
                else {
                    // -- FIXME pmm_bw = md->sys_pmmWrites;
                }
                if (pmm_bw > NVRAM_BW_THRESH) {
                    pthread_mutex_lock(&placement_lock);
                    migrate_pages(0, NVRAM_CLEAR);
                    usleep(clear_interval);
                    if (dram_usage >= DRAM_TARGET) {
                        switch_migrated = migrate_pages(MAX_N_SWITCH, SWITCH_MODE);
                        if (switch_migrated > 0) {
                            printf("DRAM<->NVRAM: Switched %d out of %ld pages.\n", switch_migrated, MAX_N_SWITCH * 2);
                        }
                    }
                    else {
                        long long n_bytes = (DRAM_LIMIT - dram_usage) * dram_sz;
                        n_pages = n_bytes / page_size;
                        n_pages = fmin(n_pages, MAX_N_FIND);
                        switch_migrated = migrate_pages(n_pages, NVRAM_INTENSIVE_MODE);

                        if (switch_migrated > 0) {
                            printf("NVRAM->DRAM: Sent %d out of %d intensive pages.\n", switch_migrated, n_pages);
                            dram_usage = free_space_tot_per(DRAM_MODE, &dram_sz);
                            nvram_usage = free_space_tot_per(NVRAM_MODE, &nvram_sz);
                        }
                    }

                    pthread_mutex_unlock(&placement_lock);
                }
            }

            n_migrated += switch_migrated;
            // -- free(md);
        }
    }

    if (thresh_act) {
        if ((dram_usage > DRAM_LIMIT) && (nvram_usage < NVRAM_TARGET)) {
            long long n_bytes = fmin((dram_usage - DRAM_TARGET) * dram_sz,
                                (NVRAM_TARGET - nvram_usage) * nvram_sz);
            n_pages = n_bytes / page_size;
            n_pages = fmin(n_pages, MAX_N_FIND);
            pthread_mutex_lock(&placement_lock);
            thresh_migrated = migrate_pages(n_pages, DRAM_MODE);
            pthread_mutex_unlock(&placement_lock);
            if (thresh_migrated > 0) {
                printf("DRAM->NVRAM: Migrated %d out of %d pages.\n", thresh_migrated, n_pages);
            }
        }
        else if (!switch_act && (nvram_usage > NVRAM_LIMIT) && (dram_usage < DRAM_TARGET)) {
            long long n_bytes = fmin((nvram_usage - NVRAM_TARGET) * nvram_sz,
                                (DRAM_TARGET - dram_usage) * dram_sz);
            n_pages = n_bytes / page_size;
            n_pages = fmin(n_pages, MAX_N_FIND);
            pthread_mutex_lock(&placement_lock);
            thresh_migrated = migrate_pages(n_pages, NVRAM_MODE);
            pthread_mutex_unlock(&placement_lock);
            if (thresh_migrated > 0) {
                printf("NVRAM->DRAM: Migrated %d out of %d pages.\n", thresh_migrated, n_pages);
            }
        }

        n_migrated += thresh_migrated;
    }

    if (n_migrated > 0) {
        sleep_interval *= 2; // give time for bw to settle given the migrated pages
        if (switch_migrated > 0) {
            sleep_interval -= clear_interval;
        }
    }
}
