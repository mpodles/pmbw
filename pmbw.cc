/******************************************************************************
 * pmbw.cc
 *
 * Parallel Memory Bandwidth Measurement / Benchmark Tool.
 *
 * The main program creates threads using the pthread library and calls the
 * assembler functions appropriate for the platform. It also uses CPUID to
 * detect which routines are applicable. The benchmark results are always
 * outputted to "stats.txt" which can then be processed using other tools.
 *
 ******************************************************************************
 * Copyright (C) 2013 Timo Bingmann <tb@panthema.net>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/

#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <algorithm>

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <pthread.h>
#include <malloc.h>

#include <stdint.h>
#include <stdio.h>

// #include "stats.h"
extern "C" {
#ifdef HAVE_DPU_COUNTERS
#include "dpu_statistics.h"
#endif
}

#if ON_WINDOWS
#include <windows.h>
#endif

// -----------------------------------------------------------------------------
// --- Global Settings and Variables

// minimum duration of test, if smaller re-run
double g_min_time = 1.0;

// target average duration of test
double g_avg_time = 1.5;

// filter of functions to run, set by command line
std::vector<const char*> gopt_funcfilter;

// set default size limit: 0 -- 4 GiB
uint64_t gopt_sizelimit_min = 0;
uint64_t gopt_sizelimit_max = 4*1024*1024*1024LLU;

// set memory limit
uint64_t gopt_memlimit = 0;

// lower and upper limit to number of threads
int gopt_nthreads_min = 0, gopt_nthreads_max = 0;

// exponentially increasing number of threads
bool gopt_nthreads_exponential = false;

// option to test permutation cycle before measurement
bool gopt_testcycle = false;

// option to change the output file from default "stats.txt"
const char* gopt_output_file = "stats.txt";

// error writers
#define ERR(x)  do { std::cerr << x << std::endl; } while(0)
#define ERRX(x)  do { (std::cerr << x).flush(); } while(0)

// allocated memory area and size
char* g_memarea = NULL;
size_t g_memsize = 0;

// global test function currently run
const struct TestFunction* g_func = NULL;

// number of physical cpus detected
int g_physical_cpus;

// hostname
char g_hostname[256];

// -----------------------------------------------------------------------------
// --- Registry for Memory Testing Functions

typedef void (*testfunc_type)(char* memarea, size_t size, size_t repeats);

struct TestFunction
{
    // identifier of the test function
    const char* name;

    // function to call
    testfunc_type func;

    // prerequisite CPU feature
    const char* cpufeat;

    // number of bytes read/written per access (for latency calculation)
    unsigned int bytes_per_access;

    // bytes skipped foward to next access point (including bytes_per_access)
    unsigned int access_offset;

    // number of accesses before and after
    unsigned int unroll_factor;

    // if 0 it's not a permutation, else, use blocks of sequential memory for each pointer
   uint8_t  permutation_size;

    // constructor which also registers the function
    TestFunction(const char* n, testfunc_type f, const char* cf,
                 unsigned int bpa, unsigned int ao, unsigned int unr,
                 uint8_t ps);

    // test CPU feature support
    bool is_supported() const;
};

std::vector<TestFunction*> g_testlist;

TestFunction::TestFunction(const char* n, testfunc_type f, const char* cf,
                           unsigned int bpa, unsigned int ao, unsigned int unr,
                           uint8_t ps)
    : name(n), func(f), cpufeat(cf),
      bytes_per_access(bpa), access_offset(ao), unroll_factor(unr),
      permutation_size(ps)
{
    g_testlist.push_back(this);
}

#define REGISTER(func, bytes_per_access, offset, unroll)                   \
    static const struct TestFunction* _##func##_register =       \
        new TestFunction(#func,func,\
            NULL,bytes_per_access,offset,unroll,false);

#define REGISTER_CPUFEAT(func, cpufeat, bytes_per_access, offset, unroll)  \
    static const struct TestFunction* _##func##_register =       \
        new TestFunction(#func,func,\
            cpufeat,bytes_per_access,offset,unroll,false);

#define REGISTER_PERM(func, bytes_per_access, perm_size)                              \
    static const struct TestFunction* _##func##_register =       \
        new TestFunction(#func,func, \
            NULL,bytes_per_access,bytes_per_access,1,perm_size);

// -----------------------------------------------------------------------------
// --- Test Functions with Inline Assembler Loops

#if __x86_64__
  #include "funcs_x86_64.h"
#elif defined(__i386__)
  #include "funcs_x86_32.h"
#elif __aarch64__
  #include "funcs_arm64.h"
#elif __arm__
  #include "funcs_arm.h"
#else
  #include "funcs_c.h"
#endif

// -----------------------------------------------------------------------------
// --- Test CPU Features via CPUID

#if defined(__i386__) || defined (__x86_64__)
//  gcc inline assembly for CPUID instruction
static inline void cpuid(int op, int out[4])
{
    asm volatile("cpuid"
                 : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3])
                 : "a" (op)
        );
}

// cpuid op 1 result
int g_cpuid_op1[4];

// check for MMX instructions
static bool cpuid_mmx()
{
    return (g_cpuid_op1[3] & ((int)1 << 23));
}

// check for SSE instructions
static bool cpuid_sse()
{
    return (g_cpuid_op1[3] & ((int)1 << 25));
}

// check for AVX instructions
static bool cpuid_avx()
{
    return (g_cpuid_op1[2] & ((int)1 << 28));
}

// run CPUID and print output
static void cpuid_detect()
{
    ERRX("CPUID:");
    cpuid(1, g_cpuid_op1);

    if (cpuid_mmx()) ERRX(" mmx");
    if (cpuid_sse()) ERRX(" sse");
    if (cpuid_avx()) ERRX(" avx");
    ERR("");
}

// TestFunction feature detection
bool TestFunction::is_supported() const
{
    if (!cpufeat) return true;
    if (strcmp(cpufeat,"mmx") == 0) return cpuid_mmx();
    if (strcmp(cpufeat,"sse") == 0) return cpuid_sse();
    if (strcmp(cpufeat,"avx") == 0) return cpuid_avx();
    return false;
}
#else
static void cpuid_detect()
{
    // replace functions with dummys
}
bool TestFunction::is_supported() const
{
    return true;
}
#endif

// -----------------------------------------------------------------------------
// --- Some Simple Subroutines

// parse a number as size_t with error detection
static inline bool
parse_uint64t(const char* value, uint64_t& out)
{
    char* endp;
    out = strtoull(value, &endp, 10);
    if (!endp) return false;
    // read additional suffix
    if (*endp == 'k' || *endp == 'K') {
        out *= 1024;
        ++endp;
    }
    else if (*endp == 'm' || *endp == 'M') {
        out *= 1024 * 1024;
        ++endp;
    }
    else if (*endp == 'g' || *endp == 'G') {
        out *= 1024 * 1024 * 1024llu;
        ++endp;
    }
    else if (*endp == 't' || *endp == 'T') {
        out *= 1024 * 1024 * 1024 * 1024llu;
        ++endp;
    }
    return (endp && *endp == 0);
}

// parse a number as int with error detection
static inline bool
parse_int(const char* value, int& out)
{
    char* endp;
    out = strtoul(value, &endp, 10);
    if (!endp) return false;
    // read additional suffix
    if (*endp == 'k' || *endp == 'K') {
        out *= 1024;
        ++endp;
    }
    else if (*endp == 'm' || *endp == 'M') {
        out *= 1024 * 1024;
        ++endp;
    }
    else if (*endp == 'g' || *endp == 'G') {
        out *= 1024 * 1024 * 1024llu;
        ++endp;
    }
    else if (*endp == 't' || *endp == 'T') {
        out *= 1024 * 1024 * 1024 * 1024llu;
        ++endp;
    }
    return (endp && *endp == 0);
}

// Simple linear congruential random generator
struct LCGRandom
{
    uint64_t      xn;

    inline LCGRandom(uint64_t seed) : xn(seed) { }

    inline uint64_t operator()()
    {
        xn = 0x27BB2EE687B0B0FDLLU * xn + 0xB504F32DLU;
        return xn;
    }
};

// return time stamp for time measurement
static inline double timestamp()
{
    struct timespec ts;
#ifdef __bgq__
    // CLOCK_MONOTONIC is not supported on BG/Q
    clock_gettime(CLOCK_REALTIME, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

// return true if the funcname is selected via command line arguments
static inline bool match_funcfilter(const char* funcname)
{
    if (gopt_funcfilter.size() == 0) return true;

    // iterate over gopt_funcfilter list
    for (size_t i = 0; i < gopt_funcfilter.size(); ++i) {
        if (strstr(funcname, gopt_funcfilter[i]) != NULL)
            return true;
    }

    return false;
}

struct Results {} g_results;

void write_results_to_file(Results results)
{
}

// pin this thread to the core, where cores are numbered 0 .. n-1
void pin_self_to_core(int core_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pthread_t current_thread = pthread_self();
    if (pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset) != 0)
        ERRX("Cannot set thread affinity for thread " << core_id << ": "
             << strerror(errno));
}

// -----------------------------------------------------------------------------
// --- List of Array Sizes to Test

const uint64_t areasize_list[] = {
    1 * 1024,                   // 1 KiB
    2 * 1024,
    3 * 1024,
    4 * 1024,
    6 * 1024,
    8 * 1024,
    12 * 1024,
    16 * 1024,
    20 * 1024,
    24 * 1024,
    28 * 1024,
    32 * 1024,
    40 * 1024,
    48 * 1024,
    64 * 1024,
    96 * 1024,
    128 * 1024,
    192 * 1024,
    256 * 1024,
    384 * 1024,
    512 * 1024,
    768 * 1024,
    1024 * 1024,                // 1 MiB
    (1024 + 256) * 1024,	// 1.25 MiB
    (1024 + 512) * 1024,	// 1.5 MiB
    (1024 + 768) * 1024,	// 1.75 MiB
    2048 * 1024,                // 2 MiB = common L2 cache size
    (2048 + 256) * 1024,	// 2.25
    (2048 + 512) * 1024,	// 2.5
    (2048 + 768) * 1024,	// 2.75
    3 * 1024 * 1024,            // 3 MiB = common L2 cache size
    4 * 1024 * 1024,            // 4 MiB
    5 * 1024 * 1024,            // 5 MiB
    6 * 1024 * 1024,            // 6 MiB = common L2 cache size
    7 * 1024 * 1024,            // 7 MiB
    8 * 1024 * 1024,            // 8 MiB = common L2 cache size
    9 * 1024 * 1024,
    10 * 1024 * 1024,
    12 * 1024 * 1024,
    14 * 1024 * 1024,
    16 * 1024 * 1024,
    20 * 1024 * 1024,
    24 * 1024 * 1024,
    28 * 1024 * 1024,
    32 * 1024 * 1024,
    40 * 1024 * 1024,
    48 * 1024 * 1024,
    56 * 1024 * 1024,
    64 * 1024 * 1024,
    128 * 1024 * 1024,
    256 * 1024 * 1024,
    512 * 1024 * 1024,
    1 * 1024 * 1024 * 1024LLU,          // 1 GiB
    2 * 1024 * 1024 * 1024LLU,
    4 * 1024 * 1024 * 1024LLU,
    8 * 1024 * 1024 * 1024LLU,
    16 * 1024 * 1024 * 1024LLU,
    32 * 1024 * 1024 * 1024LLU,
    64 * 1024 * 1024 * 1024LLU,
    128 * 1024 * 1024 * 1024LLU,
    256 * 1024 * 1024 * 1024LLU,
    512 * 1024 * 1024 * 1024LLU,
    1024 * 1024 * 1024 * 1024LLU,       // 1 TiB
    0   // list termination
};

// -----------------------------------------------------------------------------
// --- Main Program

// flag for terminating current test
bool g_done;

// global current number of threads
int g_nthreads = 0;

// synchronization barrier for current thread counter
pthread_barrier_t g_barrier;

// thread shared parameters for test function
uint64_t g_thrsize;
uint64_t g_thrsize_spaced;
uint64_t g_repeats;

// Create a one-cycle permutation of pointers in the memory area
void make_cyclic_permutation(int thread_num, void* memarea, size_t bytesize, uint8_t permutation_size)
{
    void** ptrarray = (void**)memarea;
    size_t size = bytesize / sizeof(void*);

    if (thread_num == 0)
        (std::cout << "Make permutation:").flush();

    // *** Barrier ****
    pthread_barrier_wait(&g_barrier);

    (std::cout << " filling").flush();

    for (size_t i = 0; i < size; ++i)
    {
        ptrarray[i] = &ptrarray[i]; // fill area with pointers to self-address
    }

    (std::cout << " permuting").flush();

    LCGRandom srnd((size_t)ptrarray + 233349568);

   
    // Initial array, permutation size 2
    // 0 1 2 3 4 5 6 7 8 9
    // rand 10-2=8
    // 0 1 8 9 4 5 6 7 2 3
    // rand
    // ...
    // We assume that size%permutation_size  ==0
    for (size_t n = size; n > permutation_size; n-=permutation_size)
    {
        // Find an index smaller than the already permuted end of the table
        size_t i = srnd() % (n-permutation_size);      
        i -= i%permutation_size; // Align the index to the start of the permutation block
        for(uint8_t j=0; j<permutation_size; ++j)
          std::swap( ptrarray[i+j], ptrarray[n-permutation_size+j] );
    }

    if (gopt_testcycle)
    {
        (std::cout << " testing").flush();

        void* ptr = ptrarray[0];
        size_t steps = 1;

        while ( ptr != &ptrarray[0] && steps < size*2 )
        {
            ptr = *(void**)ptr;         // walk pointer
            ++steps;
        }
        (std::cout << " cycle=" << steps).flush();

        assert(steps == size);
    }
    else
    {
        (std::cout << " cycle=" << size).flush();
    }

    // *** Barrier ****
    pthread_barrier_wait(&g_barrier);

    if (thread_num == 0)
        std::cout << std::endl;
}

void* thread_master(void* cookie)
{
    // this weirdness is because (void*) cannot be cast to int and back.
    int thread_num = *((int*)cookie);
    delete (int*)cookie;

    pin_self_to_core(thread_num);

    uint64_t factor = 1024*1024*1024;

    for (const uint64_t* areasize = areasize_list; *areasize; ++areasize)
    {
        if (*areasize < gopt_sizelimit_min && gopt_sizelimit_min != 0) {
            ERR("Skipping " << g_func->name << " test with " << *areasize
                << " minimum array size due to -s " << gopt_sizelimit_min << ".");
            continue;
        }
        if (*areasize > gopt_sizelimit_max && gopt_sizelimit_max != 0) {
            ERR("Skipping " << g_func->name << " test with " << *areasize
                << " maximum array size due to -S " << gopt_sizelimit_max << ".");
            continue;
        }

        for (unsigned int round = 0; round < 4; ++round)
        {
            // divide area by thread number
            g_thrsize = *areasize / g_nthreads;

            // unrolled tests do up to 16 accesses without loop check, thus align
            // upward to next multiple of unroll_factor*size (e.g. 128 bytes for
            // 16-times unrolled 64-bit access)
            uint64_t unrollsize = g_func->unroll_factor * g_func->bytes_per_access;
            g_thrsize = ((g_thrsize + unrollsize - 1) / unrollsize) * unrollsize;

            // total size tested
            uint64_t testsize = g_thrsize * g_nthreads;

            // skip if tests don't fit into memory
            if (g_memsize < testsize) continue;

            // due to cache thrashing in adjacent cache lines, space out
            // threads's test areas
            g_thrsize_spaced = std::max<uint64_t>(g_thrsize, 4*1024*1024 + 16*1024);

            // skip if tests don't fit into memory
            if (g_memsize < g_thrsize_spaced * g_nthreads) continue;

            g_repeats = (factor + g_thrsize-1) / g_thrsize;         // round up

            // Those metrics are crucial for stats correctness
            //
            // benchmark goes through the whole memory * g_repeats times 
            // if it's access offset (step) is larger or smaller than the amounts of bytes it reads then
            // during one repetition less or more memory is read respectively
            uint64_t testvol = testsize * g_repeats * g_func->bytes_per_access / g_func->access_offset;
            // It's whole memory we covered devided by the number of steps taken during benchmark
            // in permutation, the access_offset is set as equal to bytes_access
            uint64_t testaccess = testsize * g_repeats / g_func->access_offset;
            // Sized permutation still accesses the same underlying memory and the same amount of times
            // if(g_func->permutation_size) {
            //   testvol *= g_func->permutation_size;
            //   testaccess *= g_func->permutation_size;
            // }

            ERR("Running"
                << " nthreads=" << g_nthreads
                << " factor=" << factor
                << " areasize=" << *areasize
                << " thrsize=" << g_thrsize
                << " testsize=" << testsize
                << " repeats=" << g_repeats
                << " testvol=" << testvol
                << " testaccess=" << testaccess);

            g_done = false;
            double runtime;

            // synchronize with worker threads and run a worker ourselves
            {
                // *** Barrier ****
                pthread_barrier_wait(&g_barrier);

                assert(!g_done);

                // create cyclic permutation for each thread
                if (g_func->permutation_size>0)
                    make_cyclic_permutation(
                        thread_num, g_memarea + thread_num * g_thrsize_spaced, g_thrsize, g_func->permutation_size);
                // *** Barrier ****
                pthread_barrier_wait(&g_barrier);


                double ts1 = timestamp();
            
#ifdef HAVE_DPU_COUNTERS
            measure_start(6);
#endif
                g_func->func(g_memarea + thread_num * g_thrsize_spaced, g_thrsize, g_repeats);
#ifdef HAVE_DPU_COUNTERS
            measure_finish(6);
#endif

                // *** Barrier ****
                pthread_barrier_wait(&g_barrier);

                double ts2 = timestamp();
                runtime = ts2 - ts1;
            }

                
            // if the test was very short, it might have been optimized out by the compiler
            // skip it
            if( runtime < 0.001 ) continue;

            if ( runtime < g_min_time )
            {
                // test ran for less than one second, repeat test and scale
                // repeat factor
                factor = g_thrsize * g_repeats * g_avg_time / runtime;

                ERR("run time = " << runtime << " -> rerunning test with repeat factor=" << factor);

                --round;     // redo this areasize
            }
            else
            {
                // adapt repeat factor to observed memory bandwidth, so that
                // next test will take approximately g_avg_time sec

                factor = g_thrsize * g_repeats * g_avg_time / runtime;
                ERR("run time = " << runtime << " -> next test with repeat factor=" << factor);

                std::ostringstream result;
                // result << "RESULT\t";

                // write_results_to_file(Results();
                // output date, time and hostname to result line
                char datetime[64];
                time_t tnow = time(NULL);

                strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", localtime(&tnow));
                result << "{" ; //<< datetime << '\t';
                result << "\"datetime\": \"" << datetime << "\", \t"
                       << "\"host\": \"" << g_hostname << "\", \t"
                       << "\"version\": \"" << PACKAGE_VERSION << "\", \t"
                       << "\"funcname\": \"" << g_func->name << "\", \t"
                       << "\"nthreads\": \"" << g_nthreads << "\", \t"
                       << "\"areasize\": \"" << *areasize << "\", \t"
                       << "\"threadsize\": \"" << g_thrsize << "\", \t"
                       << "\"testsize\": \"" << testsize << "\", \t"
                       << "\"repeats\": \"" << g_repeats << "\", \t"
                       << "\"testvol\": \"" << testvol << "\", \t"
                       << "\"testaccess\": \"" << testaccess << "\", \t"
                       << "\"time\": \"" << std::setprecision(20) << runtime << "\", \t"
                       << "\"bandwidth\": \"" << testvol / runtime << "\", \t"
                       << "\"rate\": \"" << runtime / testaccess<< "\", \t";

                result << "}";
                std::cout << result.str() << std::endl;

                std::ofstream resultfile(gopt_output_file, std::ios::app);
                resultfile << result.str() << std::endl;
            }
        }
    }

    g_done = true;

    // *** Barrier ****
    pthread_barrier_wait(&g_barrier);
    return NULL;
}

void* thread_worker(void* cookie)
{
    // this weirdness is because (void*) cannot be cast to int and back.
    int thread_num = *((int*)cookie);
    delete (int*)cookie;

    pin_self_to_core(thread_num);

    while (1)
    {
        // *** Barrier ****
        pthread_barrier_wait(&g_barrier);

        if (g_done) break;

        // create cyclic permutation for each thread
        if (g_func->permutation_size >0)
            make_cyclic_permutation(
                thread_num, g_memarea + thread_num * g_thrsize_spaced, g_thrsize, g_func->permutation_size);

        // *** Barrier ****
        pthread_barrier_wait(&g_barrier);
        // start_dpu_thread_counters(thread_num);

        g_func->func(g_memarea + thread_num * g_thrsize_spaced, g_thrsize, g_repeats);

        // *** Barrier ****
        pthread_barrier_wait(&g_barrier);
        // update_dpu_thread_counters(thread_num);
    }

    return NULL;
}

void run_func_by_threads(const TestFunction* func)
{
    if (!match_funcfilter(func->name)) {
        ERR("Skipping " << func->name << " tests");
        return;
    }

    int nthreads = 1;

    if (gopt_nthreads_min != 0)
        nthreads = gopt_nthreads_min;

    if (gopt_nthreads_max == 0)
        gopt_nthreads_max = g_physical_cpus + 2;

    bool exp_have_physical = false;

    while (1)
    {
        // globally set test function and thread number
        g_func = func;
        g_nthreads = nthreads;

        // create barrier and run threads
        pthread_barrier_init(&g_barrier, NULL, nthreads);

        pthread_t thr[nthreads];
        pthread_create(&thr[0], NULL, thread_master, new int(0));
        for (int p = 1; p < nthreads; ++p)
            pthread_create(&thr[p], NULL, thread_worker, new int(p));

        for (int p = 0; p < nthreads; ++p)
            pthread_join(thr[p], NULL);

        pthread_barrier_destroy(&g_barrier);

        // increase thread count
        if (nthreads >= gopt_nthreads_max) break;

        if (gopt_nthreads_exponential)
            nthreads = 2 * nthreads;
        else
            nthreads++;

        // Prevent the next check from running the tests with g_physical_cpus
        // twice if that is a power of two
        if (gopt_nthreads_exponential && nthreads == g_physical_cpus)
            exp_have_physical = true;

        if (gopt_nthreads_exponential && nthreads > g_physical_cpus &&
            !exp_have_physical) {
            // Halve it because we want both with and without hyperthreading.
            // The next iteration will then have nthreads == g_physical_cpus,
            // and the one after that will be the last with gopt_nthreads_max.
            nthreads = g_physical_cpus / 2;
            exp_have_physical = true;
        }

        if (nthreads > gopt_nthreads_max)
            nthreads = gopt_nthreads_max;
    }
}

static inline uint64_t round_up_power2(uint64_t v)
{
    v--;
    v |= v >> 1;     v |= v >> 2;
    v |= v >> 4;     v |= v >> 8;
    v |= v >> 16;    v |= v >> 32;
    v++;
    return v + (v == 0);
}

void print_usage(const char* prog)
{
    ERR("Usage: " << prog << " [options]" << std::endl
        << "Options:" << std::endl
        << "  -f <match>     Run only benchmarks containing this substring, can be used multile times. Try \"list\"." << std::endl
        << "  -M <size>      Limit the maximum amount of memory allocated at startup [byte]." << std::endl
        << "  -o <file>      Write the results to <file> instead of stats.txt." << std::endl
        << "  -p <nthrs>     Run benchmarks with at least this thread count." << std::endl
        << "  -P <nthrs>     Run benchmarks with at most this thread count (overrides detected processor count)." << std::endl
        << "  -Q             Run benchmarks with exponentially increasing thread count." << std::endl
        << "  -s <size>      Limit the _minimum_ test array size [byte]. Set to 0 for no limit." << std::endl
        << "  -S <size>      Limit the _maximum_ test array size [byte]. Set to 0 for no limit." << std::endl
        );
}

int main(int argc, char* argv[])
{
    // *** parse command line options

    std::cout <<"CPP version: "<<__cplusplus<<std::endl;
    int opt;

    while ( (opt = getopt(argc, argv, "hf:M:o:p:P:Qs:S:")) != -1 )
    {
        switch (opt) {
        default:
        case 'h':
            print_usage(argv[0]);
            return EXIT_FAILURE;

        case 'f':
            if (strcmp(optarg,"list") == 0)
            {
                // *** run CPUID
                cpuid_detect();

                std::cout << "Test Function List" << std::endl;
                for (size_t i = 0; i < g_testlist.size(); ++i)
                {
                    if (!g_testlist[i]->is_supported()) continue;
                    if (!match_funcfilter(g_testlist[i]->name)) continue;

                    std::cout << "  " << g_testlist[i]->name << std::endl;
                }
                return 0;
            }

            gopt_funcfilter.push_back(optarg);

            ERR("Running only functions containing '" << optarg << "'");
            break;

        case 'M':
            if (!parse_uint64t(optarg, gopt_memlimit)) {
                ERR("Invalid parameter for -M <memory limit>.");
                exit(EXIT_FAILURE);
            }
            else if (gopt_memlimit == 0) {
                ERR("Lifting memory limit: allocating highest power of two fitting into RAM.");
            }
            else {
                ERR("Setting memory limit to " << gopt_memlimit << ".");
            }
            break;

        case 'o':
            gopt_output_file = optarg;
            ERR("Writing results to " << gopt_output_file << ".");
            break;

        case 'Q':
            ERR("Running benchmarks with exponentially increasing thread counts.");
            gopt_nthreads_exponential = true;
            break;

        case 'p':
            if (!parse_int(optarg, gopt_nthreads_min)) {
                ERR("Invalid parameter for -p <lower nthreads limit>.");
                exit(EXIT_FAILURE);
            }
            else {
                ERR("Running benchmarks with at least " << gopt_nthreads_min << " threads.");
            }
            break;

        case 'P':
            if (!parse_int(optarg, gopt_nthreads_max)) {
                ERR("Invalid parameter for -p <upper nthreads limit>.");
                exit(EXIT_FAILURE);
            }
            else {
                ERR("Running benchmarks with up to " << gopt_nthreads_max << " threads.");
            }
            break;

        case 's':
            if (!parse_uint64t(optarg, gopt_sizelimit_min)) {
                ERR("Invalid parameter for -s <minimum size limit>.");
                exit(EXIT_FAILURE);
            }
            else if (gopt_sizelimit_min == 0) {
                ERR("Running benchmarks with no lower array size limit.");
            }
            else {
                ERR("Running benchmarks with array size at least " << gopt_sizelimit_min << ".");
            }
            break;

        case 'S':
            if (!parse_uint64t(optarg, gopt_sizelimit_max)) {
                ERR("Invalid parameter for -S <maximum size limit>.");
                exit(EXIT_FAILURE);
            }
            else if (gopt_sizelimit_max == 0) {
                ERR("Running benchmarks with no upper array size limit.");
            }
            else {
                ERR("Running benchmarks with array size up to " << gopt_sizelimit_max << ".");
            }
            break;
        }
    }

#if !ON_WINDOWS
    gethostname(g_hostname, sizeof(g_hostname));
#else
    DWORD hostnameSize = sizeof(g_hostname);
    GetComputerName(g_hostname, &hostnameSize);
#endif

    // *** run CPUID
    cpuid_detect();

    // *** allocate memory for tests

#if !ON_WINDOWS

    size_t physical_mem = sysconf(_SC_PHYS_PAGES) * (size_t)sysconf(_SC_PAGESIZE);
    g_physical_cpus = sysconf(_SC_NPROCESSORS_ONLN);

#else

    MEMORYSTATUSEX memstx;
    memstx.dwLength = sizeof(memstx);
    GlobalMemoryStatusEx(&memstx);

    size_t physical_mem = memstx.ullTotalPhys;

    SYSTEM_INFO sysinfo;
    GetSystemInfo( &sysinfo );

    g_physical_cpus = sysinfo.dwNumberOfProcessors;

#endif

    ERR("Detected " << physical_mem / 1024/1024 << " MiB physical RAM and " << g_physical_cpus << " CPUs. " << std::endl);

    // limit allocated memory via command line
    if (gopt_memlimit && gopt_memlimit < physical_mem)
        physical_mem = gopt_memlimit;

    // round down memory to largest power of two, still fitting in physical RAM
    g_memsize = round_up_power2(physical_mem) / 2;

    // due to roundup in loop to next cache-line size, add one extra cache-line per thread
    g_memsize += g_physical_cpus * 256;

    // I don't remember why I needed that
    // g_memsize  /= 4;
    ERR("Allocating " << g_memsize / 1024/1024 << " MiB for testing.");

    // allocate memory area

#if HAVE_POSIX_MEMALIGN

    if (posix_memalign((void**)&g_memarea, 32, g_memsize) != 0) {
        ERR("Error allocating memory.");
        return -1;
    }

#else

    g_memarea = (char*)malloc(g_memsize);

#endif

    // fill memory with junk, but this allocates physical memory
    memset(g_memarea, 1, g_memsize);

    // *** perform memory tests

    unlink(gopt_output_file);

    for (size_t i = 0; i < g_testlist.size(); ++i)
    {
        TestFunction* tf = g_testlist[i];

        if (!tf->is_supported())
        {
            ERR("Skipping " << tf->name << " test "
                << "due to missing CPU feature '" << tf->cpufeat << "'.");
            continue;
        }

        run_func_by_threads(tf);
    }

    // cleanup

    free(g_memarea);

    for (size_t i = 0; i < g_testlist.size(); ++i)
        delete g_testlist[i];

    return 0;
}
