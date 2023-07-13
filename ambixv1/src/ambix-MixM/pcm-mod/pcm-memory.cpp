/*

   Copyright (c) 2009-2020, Intel Corporation
   All rights reserved.

   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of Intel Corporation nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
// written by Patrick Lu
// increased max sockets to 256 - Thomas Willhalm


/*!     \file pcm-memory.cpp
  \brief Example of using CPU counters: implements a performance counter monitoring utility for memory controller channels and DIMMs (ranks) + PMM memory traffic
  */
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> // for gettimeofday()
#include <math.h>
#include <iomanip>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <assert.h>
#include "cpucounters.h"
#include "utils.h"
#include "../pcm-ambix.h"


using namespace std;
using namespace pcm;

uint32 max_imc_channels = ServerUncoreCounterState::maxChannels;
const uint32 max_imc_controllers = ServerUncoreCounterState::maxControllers;

PCM *m = PCM::getInstance();
uint32 numSockets;
ServerUncoreCounterState * BeforeState;
ServerUncoreCounterState * AfterState;
uint32 BeforeTime;
uint32 AfterTime;

bool pmm = (PMM_MIXED == 0 ? true : false);
bool pmmMixed = !pmm;

memdata_t md;

void print_help(const string prog_name)
{
    cerr << "\n Usage: \n " << prog_name
         << " --help | [delay] [options] [-- external_program [external_program_options]]\n";
    cerr << "   <delay>                           => time interval to sample performance counters.\n";
    cerr << "                                        If not specified, or 0, with external program given\n";
    cerr << "                                        will read counters only after external program finishes\n";
    cerr << " Supported <options> are: \n";
    cerr << "  -h    | --help  | /h               => print this help and exit\n";
    cerr << " Examples:\n";
    cerr << "  " << prog_name << " 1                  => print counters every second without core and socket output\n";
    cerr << "\n";
}

void display_sys_bandwidth(memdata_t *md)
{
    cout.setf(ios::fixed);
    cout.precision(2);

    cout << "\
        \r|---------------------------------|  System  |-----------------------------------|\n";
    cout << "\
        \r|--                   DRAM Read Throughput(MB/s):" << setw(14) << md->sys_dramReads <<                                           "                --|\n\
        \r|--                  DRAM Write Throughput(MB/s):" << setw(14) << md->sys_dramWrites <<                                          "                --|\n\
        \r|--                    PMM Read Throughput(MB/s):" << setw(14) << md->sys_pmmReads <<                                            "                --|\n\
        \r|--                   PMM Write Throughput(MB/s):" << setw(14) << md->sys_pmmWrites <<                                           "                --|\n";

    if (PMM_MIXED) {
        cout << "\
            \r|--                      PMM AD Throughput(MB/s):" << setw(14) << md->sys_pmmAppBW <<                                            "                --|\n\
            \r|--                      PMM MM Throughput(MB/s):" << setw(14) << md->sys_pmmMemBW <<                                           "                --|\n";
    }
    cout << "\
        \r|--                        Read Throughput(MB/s):" << setw(14) << md->sys_dramReads+md->sys_pmmReads <<                              "                --|\n\
        \r|--                       Write Throughput(MB/s):" << setw(14) << md->sys_dramWrites+md->sys_pmmWrites <<                            "                --|\n\
        \r|--                      Memory Throughput(MB/s):" << setw(14) << md->sys_dramReads+md->sys_dramWrites+md->sys_pmmReads+md->sys_pmmWrites << "                --|\n\
        \r|--                      Total DRAM Read (MEv/s):" << setw(14) << md->total_rDram << "                --|\n\
        \r|--                     Total DRAM Write (MEv/s):" << setw(14) << md->total_wDram << "                --|\n\
        \r|--                    Total Optane Read (MEv/s):" << setw(14) << md->total_rOptane << "                --|\n\
        \r|--                   Total Optane Write (MEv/s):" << setw(14) << md->total_wOptane << "                --|\n\
        \r|---------------------------------------||---------------------------------------|\n";
}

void write_memdata(memdata_t md) {

    FILE * out_file;
    out_file = fopen("memdata.tmp", "w");
    fwrite(&md, sizeof(md), 1, out_file);
    fclose(out_file);

    rename("memdata.tmp", PCM_FILE_NAME);

    FILE * txt_file;
    txt_file = fopen("pcmEvents.tmp", "w");
    fprintf(txt_file, "R_DRAM: %lu\nW_DRAM: %lu\nR_OPT: %lu\nW_OPT: %lu\n", md.total_rDram, md.total_wDram, md.total_rOptane, md.total_wOptane);
    fclose(txt_file);

    rename("pcmEvents.tmp", "pcmEvents.txt");
}


memdata_t calculate_bandwidth(const ServerUncoreCounterState uncState1[], const ServerUncoreCounterState uncState2[], const uint64 elapsedTime)
{
    //uint64 pmmMemoryModeCleanMisses = 0, pmmMemoryModeDirtyMisses = 0;

    md.sys_dramReads = 0.0;
    md.sys_dramWrites = 0.0;
    md.sys_pmmReads = 0.0;
    md.sys_pmmWrites = 0.0;

    md.sys_pmmAppBW = 0.0;
    md.sys_pmmMemBW = 0.0;

    auto toBW = [&elapsedTime](const uint64 nEvents)
    {
        return (float)(nEvents * 64 / 1000000.0 / (elapsedTime / 1000.0));
    };
    auto toMEv = [&elapsedTime](const uint64 nEvents)
    {
        return (uint64)(nEvents / 1000000);
    };

    for(uint32 skt=0; skt < numSockets; ++skt)
    {
        for (uint32 channel = 0; channel < max_imc_channels; ++channel)
        {
            uint64 reads = 0, writes = 0, pmmReads = 0, pmmWrites = 0, pmmMemoryModeCleanMisses = 0, pmmMemoryModeDirtyMisses = 0;

            reads = getMCCounter(channel, ServerPCICFGUncore::EventPosition::READ, uncState1[skt], uncState2[skt]);
            writes = getMCCounter(channel, ServerPCICFGUncore::EventPosition::WRITE, uncState1[skt], uncState2[skt]);

            if (pmm) {
                pmmReads = getMCCounter(channel, ServerPCICFGUncore::EventPosition::PMM_READ, uncState1[skt], uncState2[skt]);
                pmmWrites = getMCCounter(channel, ServerPCICFGUncore::EventPosition::PMM_WRITE, uncState1[skt], uncState2[skt]);
            }
            else if (pmmMixed) {
                pmmMemoryModeCleanMisses = getMCCounter(channel, ServerPCICFGUncore::EventPosition::PMM_MM_MISS_CLEAN, uncState1[skt], uncState2[skt]);
                pmmMemoryModeDirtyMisses = getMCCounter(channel, ServerPCICFGUncore::EventPosition::PMM_MM_MISS_DIRTY, uncState1[skt], uncState2[skt]);
            }

            if ((reads + writes + pmmReads + pmmWrites + pmmMemoryModeCleanMisses + pmmMemoryModeDirtyMisses) == 0)
            {
                continue;
            }

            md.total_rDram += toMEv(reads);
            md.total_wDram += toMEv(writes);

            md.sys_dramReads += toBW(reads);
            md.sys_dramWrites += toBW(writes);

            if (pmm) {
                md.total_rOptane += toMEv(pmmReads);
                md.total_wOptane += toMEv(pmmWrites);

                md.sys_pmmReads += toBW(pmmReads);
                md.sys_pmmWrites += toBW(pmmWrites);
            }
            else if (pmmMixed) {
                md.sys_pmmMemBW += toBW(pmmMemoryModeCleanMisses + 2 * pmmMemoryModeDirtyMisses);
            }
        }

        if (pmmMixed) {
            for(uint32 c = 0; c < max_imc_controllers; ++c) {
                uint64 pmmReads = 0, pmmWrites = 0;
                pmmReads = getM2MCounter(c, ServerPCICFGUncore::EventPosition::PMM_READ, uncState1[skt],uncState2[skt]);
                pmmWrites = getM2MCounter(c, ServerPCICFGUncore::EventPosition::PMM_WRITE, uncState1[skt],uncState2[skt]);

                md.total_rOptane += toMEv(pmmReads);
                md.total_wOptane += toMEv(pmmWrites);

                md.sys_pmmReads += toBW(pmmReads);
                md.sys_pmmWrites += toBW(pmmWrites);
            }
        }
    }

    if (pmmMixed) {
        md.sys_pmmAppBW = max(md.sys_pmmReads + md.sys_pmmWrites - md.sys_pmmMemBW, float(0.0));
    }

    return md;
}

int main(int argc, char * argv[])
{
    set_signal_handlers();

#ifdef PCM_FORCE_SILENT
    null_stream nullStream1, nullStream2;
    cout.rdbuf(&nullStream1);
    cerr.rdbuf(&nullStream2);
#endif

    cerr << "\n";
    cerr << " Processor Counter Monitor: Memory Bandwidth Monitoring Utility " << PCM_VERSION << "\n";
    cerr << "\n";

    cerr << " This utility measures memory bandwidth per channel or per DIMM rank in real-time\n";
    cerr << "\n";

    string program = string(argv[0]);


    if (argc > 1) do
    {
        argv++;
        argc--;
        if (strncmp(*argv, "--help", 6) == 0 ||
            strncmp(*argv, "-h", 2) == 0 ||
            strncmp(*argv, "/h", 2) == 0)
        {
            print_help(program);
            exit(EXIT_FAILURE);
        }
    } while(argc > 1); // end of command line parsing loop

    m->disableJKTWorkaround();
    print_cpu_details();
    if (!m->hasPCICFGUncore())
    {
        cerr << "Unsupported processor model (" << m->getCPUModel() << ").\n";
        if (m->memoryTrafficMetricsAvailable())
            cerr << "For processor-level memory bandwidth statistics please use pcm.x\n";
        exit(EXIT_FAILURE);
    }
    if ((m->PMMTrafficMetricsAvailable()) == false)
    {
        cerr << "PMM traffic metrics are not available on your processor.\n";
        exit(EXIT_FAILURE);
    }
    PCM::ErrorCode status = m->programServerUncoreMemoryMetrics(-1, -1, pmm || pmmMixed, pmmMixed);
    switch (status)
    {
        case PCM::Success:
            break;
        case PCM::MSRAccessDenied:
            cerr << "Access to Processor Counter Monitor has denied (no MSR or PCI CFG space access).\n";
            exit(EXIT_FAILURE);
        case PCM::PMUBusy:
            cerr << "Access to Processor Counter Monitor has denied (Performance Monitoring Unit is occupied by other application). Try to stop the application that uses PMU.\n";
            cerr << "Alternatively you can try to reset PMU configuration at your own risk. Try to reset? (y/n)\n";
            char yn;
            cin >> yn;
            if ('y' == yn)
            {
                m->resetPMU();
                cerr << "PMU configuration has been reset. Try to rerun the program again.\n";
            }
            exit(EXIT_FAILURE);
        default:
            cerr << "Access to Processor Counter Monitor has denied (Unknown error).\n";
            exit(EXIT_FAILURE);
    }

    numSockets = m->getNumSockets();
    if(numSockets > MAX_SOCKETS)
    {
        cerr << "Only systems with up to " << MAX_SOCKETS << " sockets are supported! Program aborted\n";
        exit(EXIT_FAILURE);
    }

    max_imc_channels = m->getMCChannelsPerSocket();

    BeforeState = new ServerUncoreCounterState[numSockets];
    AfterState = new ServerUncoreCounterState[numSockets];
    BeforeTime = 0;
    AfterTime = 0;

    m->setBlocked(false);

    cerr << "Update every " << PCM_DELAY << " seconds\n";

    for(uint32 i=0; i<numSockets; ++i)
        BeforeState[i] = m->getServerUncoreCounterState(i);

    BeforeTime = m->getTickCount();

    // Init MD

    md.sys_dramReads = 0.0;
    md.sys_dramWrites = 0.0;
    md.sys_pmmReads = 0.0;
    md.sys_pmmWrites = 0.0;

    md.sys_pmmAppBW = 0.0;
    md.sys_pmmMemBW = 0.0;

    md.total_rDram = 0;
    md.total_wDram = 0;
    md.total_rOptane = 0;
    md.total_wOptane = 0;

    while (true)
    {
        MySleep(PCM_DELAY);

        AfterTime = m->getTickCount();
        for(uint32 i=0; i<numSockets; ++i)
            AfterState[i] = m->getServerUncoreCounterState(i);

        calculate_bandwidth(BeforeState,AfterState,AfterTime-BeforeTime);
        write_memdata(md);
        display_sys_bandwidth(&md);

        swap(BeforeTime, AfterTime);
        swap(BeforeState, AfterState);
    }

    delete[] BeforeState;
    delete[] AfterState;

    exit(EXIT_SUCCESS);
}
