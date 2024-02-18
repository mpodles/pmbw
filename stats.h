#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <tuple>

#include <utilities.h>

enum status {
  SUCCESS,
  ERROR_NOT_FOUND,
  IO_FAILED,
  INVALID_USE,
  NO_MEMORY,
  BAD_STATE
};

#define THREADS_COUNT 8
typedef struct { 
  
  struct {
    uint64_t memory_reads;
    uint64_t memory_writes;
  } per_thread_stats[THREADS_COUNT]; 

  std::map<std::string, std::tuple<std::string, uint64_t, std::string>> counters;
  // uint64_t l3_half0_bank0_hit;
  // uint64_t l3_half1_bank0_hit;
  // uint64_t l3_half0_bank1_hit;
  // uint64_t l3_half1_bank1_hit;
  //
  // uint64_t l3_half0_bank0_miss;
  // uint64_t l3_half1_bank0_miss;
  // uint64_t l3_half0_bank1_miss;
  // uint64_t l3_half1_bank1_miss;
} dpu_statistics;

static dpu_statistics g_dpu_stats;
// This structure is returned each time the main measurement is read.
// It contains the result of all the measurements, taken simultaneously.
// The order of the measurements is unknown - used the ID.
#define EVENTS_MEASURED 4
typedef struct {
  uint64_t recorded_values;
  struct {
    uint64_t value;
    uint64_t id;
  } values[EVENTS_MEASURED];
} measurement_t;

// The main measuring group.
perf_measurement_t *all_measurements;
// Retired instructions. Be careful, these can be affected by various issues, most notably hardware interrupt counts.
perf_measurement_t *measure_instruction_count;
// Total cycles; not affected by CPU frequency scaling.
perf_measurement_t *measure_cycle_count;
// This counts context switches. Until Linux 2.6.34, these were all reported as user-space events, after that they are reported as happening in the kernel.
perf_measurement_t *measure_context_switches;
// This reports the CPU clock, a high-resolution per-CPU timer.
// See also: https://stackoverflow.com/questions/23965363/linux-perf-events-cpu-clock-and-task-clock-what-is-the-difference.
perf_measurement_t *measure_cpu_clock;
// This counts the number of branch misses branch misses. Retired branch instructions.  Prior to Linux 2.6.35, this used the wrong event on AMD processors
perf_measurement_t *measure_cpu_branches;

perf_measurement_t *measure_l1_read_hit;
perf_measurement_t *measure_l1_read_miss;

perf_measurement_t *measure_ll_read_hit;
perf_measurement_t *measure_ll_read_miss;
static int prepared_successfully = 0;

// // Call prepare before executing main
// void prepare() __attribute__((constructor));
// Call cleanup before exiting
// void cleanup() __attribute__((destructor));

void assert_support() {
  // Print the kernel version
  int major, minor, patch;
  int status = perf_get_kernel_version(&major, &minor, &patch);
  if (status < 0) {
    perf_print_error(status);
    exit(EXIT_FAILURE);
  }

  fprintf(stderr, "Kernel version: %d.%d.%d\n", major, minor, patch);

  // Exit if the API is unsupported
  status = perf_is_supported();
  if (status < 0) {
    perf_print_error(status);
    exit(EXIT_FAILURE);
  } else if (status == 0) {
    fprintf(stderr, "error: perf not supported\n");
    exit(EXIT_FAILURE);
  }
}

void prepare_measurement(const char *description, perf_measurement_t *measurement, perf_measurement_t *parent_measurement) {
  int status = perf_has_sufficient_privilege(measurement);
  if (status < 0) {
    perf_print_error(status);
    exit(EXIT_FAILURE);
  } else if (status == 0) {
    fprintf(stderr, "error: unprivileged user\n");
    exit(EXIT_FAILURE);
  }

  int support_status = perf_event_is_supported(measurement);
  if (support_status < 0) {
    perf_print_error(support_status);
    exit(EXIT_FAILURE);
  } else if (support_status == 0) {
    fprintf(stderr, "warning: %s not supported\n", description);
    return;
  }

  int group = parent_measurement == NULL ? -1 : parent_measurement->file_descriptor;

  status = perf_open_measurement(measurement, group, 0);
  if (status < 0) {
    perf_print_error(status);
    exit(EXIT_FAILURE);
  }
}

void prepare_perf_measurements() {
  fprintf(stderr, "preparing harness\n");

  // Fail if the perf API is unsupported
  assert_support();

  // Create a measurement using hardware (CPU) registers. Measure the number of cycles.
  measure_cycle_count = perf_create_measurement(PERF_TYPE_HARDWARE, 
                                            PERF_COUNT_HW_CPU_CYCLES,
                                            0,
                                            -1);
  prepare_measurement("cycles", measure_cycle_count, NULL);

  measure_l1_read_hit = perf_create_measurement(PERF_TYPE_HW_CACHE, 
                                            (PERF_COUNT_HW_CACHE_L1D | PERF_COUNT_HW_CACHE_OP_READ<<8 | PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
                                            0,
                                            -1);
  prepare_measurement("l1_read_hit", measure_l1_read_hit, measure_cycle_count);

  measure_l1_read_miss = perf_create_measurement(PERF_TYPE_HW_CACHE, 
                                            (PERF_COUNT_HW_CACHE_L1D | PERF_COUNT_HW_CACHE_OP_READ<<8 | PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                                            0,
                                            -1);
  prepare_measurement("l1_read_miss", measure_l1_read_miss, measure_cycle_count);

  measure_ll_read_hit = perf_create_measurement(PERF_TYPE_HW_CACHE, 
                                            (PERF_COUNT_HW_CACHE_LL | PERF_COUNT_HW_CACHE_OP_READ<<8 | PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
                                            0,
                                            -1);
  prepare_measurement("ll_read_hit", measure_ll_read_hit, measure_cycle_count);

  measure_ll_read_miss = perf_create_measurement(PERF_TYPE_HW_CACHE, 
                                            (PERF_COUNT_HW_CACHE_LL  | PERF_COUNT_HW_CACHE_OP_READ<<8 | PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                                            0,
                                            -1);
  prepare_measurement("ll_read_miss", measure_ll_read_miss, measure_cycle_count);

  // Mark the preparation stage as successfuly
  prepared_successfully = 1;
}

void cleanup_perf() {
  fprintf(stderr, "cleaning up harness\n");
  if (all_measurements != NULL) {
    perf_close_measurement(all_measurements);
    free((void *)all_measurements);
  }

  if (measure_instruction_count != NULL) {
    perf_close_measurement(measure_instruction_count);
    free((void *)measure_instruction_count);
  }

  if (measure_cycle_count != NULL) {
    perf_close_measurement(measure_cycle_count);
    free((void *)measure_cycle_count);
  }

  if (measure_context_switches != NULL) {
    perf_close_measurement(measure_context_switches);
    free((void *)measure_context_switches);
  }

  if (measure_cpu_clock != NULL) {
    perf_close_measurement(measure_cpu_clock);
    free((void *)measure_cpu_clock);
  }

  if (measure_l1_read_hit != NULL) {
    perf_close_measurement(measure_l1_read_hit);
    free((void *)measure_l1_read_hit);
  }

  if (measure_l1_read_miss != NULL) {
    perf_close_measurement(measure_l1_read_miss);
    free((void *)measure_l1_read_miss);
  }

  if (measure_ll_read_hit != NULL) {
    perf_close_measurement(measure_ll_read_hit);
    free((void *)measure_ll_read_hit);
  }

  if (measure_ll_read_miss != NULL) {
    perf_close_measurement(measure_ll_read_miss);
    free((void *)measure_ll_read_miss);
  }
}


void print_dpu_measurements(std::ostringstream &result) {
  for(auto& pair: g_dpu_stats.counters){
    result<<"\""<<pair.first<<"\":\""<<std::get<1>(pair.second)<<"\",";
  }
  // result<<"\"l3_half0_bank0_hit\":\"" <<g_dpu_stats.l3_half0_bank0_hit<< "\","
  //       <<"\"l3_half0_bank1_hit\":\"" <<g_dpu_stats.l3_half0_bank1_hit<< "\","
  //       <<"\"l3_half0_bank0_miss\":\"" <<g_dpu_stats.l3_half0_bank0_miss<< "\","
  //       <<"\"l3_half0_bank1_miss\":\"" <<g_dpu_stats.l3_half0_bank1_miss<< "\","
  //       <<"\"l3_half1_bank0_hit\":\"" <<g_dpu_stats.l3_half1_bank0_hit<< "\","
  //       <<"\"l3_half1_bank1_hit\":\"" <<g_dpu_stats.l3_half1_bank1_hit<< "\","
  //       <<"\"l3_half1_bank0_miss\":\"" <<g_dpu_stats.l3_half1_bank0_miss<< "\","
  //       <<"\"l3_half1_bank1_miss\":\"" <<g_dpu_stats.l3_half1_bank1_miss<< "\",";
  result<<" \"thread_stats\""<<":[";
  for(uint8_t thr=0; thr<THREADS_COUNT; ++thr) {
    result<<"{\"memory_reads\":\"" <<g_dpu_stats.per_thread_stats[thr].memory_reads << "\","
          << "\"memory_writes\":\"" << g_dpu_stats.per_thread_stats[thr].memory_writes << "\"}";
    if(thr!=THREADS_COUNT-1)
      result<<",";
  }
  result<<" ],"<<'\t';
}

void print_perf_measurements(std::ostringstream &result, measurement_t *measurement) {
    uint64_t values[EVENTS_MEASURED + 1] = {0};
    // perf_measurement_t *taken_measurements[] = {all_measurements, measure_instruction_count, measure_cycle_count, measure_context_switches, measure_cpu_clock, measure_cpu_branches, measure_l1_read_hit};

    perf_measurement_t *taken_measurements[] = {measure_cycle_count, measure_l1_read_hit, measure_l1_read_miss, measure_ll_read_hit, measure_ll_read_miss};
    for (uint64_t j = 0; j < measurement->recorded_values; j++) {
      for (int k = 0; k < EVENTS_MEASURED + 1; k++) {
        if (measurement->values[j].id == taken_measurements[k]->id) {
          values[k] = measurement->values[j].value;
          break;
        }
      }
    }
    // // Ignore the results from the dummy counter
    // result<<" instructions="<<values[1]<< '\t'<<
    //         " cycles=" <<values[2]<< '\t'<<
    //         " context_switches=" <<values[3]<< '\t'<<
    //         " clock=" <<values[4]<< '\t'<<
    //         " cpu_branches=" <<values[5]<< '\t'<<
    //         " l1_read_hit=" <<values[6];
    result<<" \"l1_read_hit\":\""<<values[1]<<"\",\t"
          <<" \"l1_read_miss\":\""<<values[2]<<"\",\t"
          <<" \"ll_read_hit\":\""<<values[3]<<"\",\t"
          <<" \"ll_read_miss\":\""<<values[4]<<"\"\t";
}
//   .per_thread_stats = {}
//   // .memory_read = 0,
//   // .memory_write = 0,
//   // .reads_difference=0,
//   // .writes_difference=0,
// };

int
read_file(char const *path, char **out_bytes, size_t *out_bytes_len)
{
	FILE *file;
	char *bytes;

	file = fopen(path, "rb");
	if (file == NULL)
		return ERROR_NOT_FOUND;

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return IO_FAILED;
	}

	long const nb_file_bytes = ftell(file);

	if (nb_file_bytes == -1) {
		fclose(file);
		return IO_FAILED;
	}

	if (nb_file_bytes == 0) {
		fclose(file);
		return INVALID_USE;
	}

	bytes = (char *)malloc(nb_file_bytes);
	if (bytes == NULL) {
		fclose(file);
		return NO_MEMORY;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		free(bytes);
		fclose(file);
		return IO_FAILED;
	}

	size_t const read_byte_count = fread(bytes, 1, nb_file_bytes, file);

	fclose(file);

	// if (read_byte_count != (size_t)nb_file_bytes) {
	// 	free(bytes);
	// 	return DOCA_ERROR_IO_FAILED;
	// }

	*out_bytes = bytes;
	*out_bytes_len = read_byte_count;
	return 0;
}

int
open_file(const char *fname, FILE **file, const char *mode)
{
    // char fname[100];
    // sprintf(fname, "/tmp/build/stats%d", test_num);
    *file = fopen(fname, mode);

    if(*file == NULL)
    {
      return BAD_STATE;
    }
  return SUCCESS;
}

int
read_dpu_counter_file(std::string fname, uint64_t *counter)
{
  char *file_contents;
  uint64_t file_len;
  int result = read_file(fname.c_str(), &file_contents, &file_len);
  // Last byte is /n, replace it with string end for correct parsing
  file_contents[file_len] = 0;
  *counter = strtouq(file_contents, NULL, 0);
  free(file_contents);

  return result;
}

void 
init_dpu_counters()
{

  g_dpu_stats.counters["l3_half0_bank0_hit"]= std::make_tuple("/sys/class/hwmon/hwmon0/l3cachehalf0/%s1", 0, "0x17");
  g_dpu_stats.counters["l3_half0_bank1_hit"]= std::make_tuple("/sys/class/hwmon/hwmon0/l3cachehalf0/%s2",  0, "0x18");
  g_dpu_stats.counters["l3_half0_bank0_miss"]= std::make_tuple("/sys/class/hwmon/hwmon0/l3cachehalf0/%s3",  0, "0x19");
  g_dpu_stats.counters["l3_half0_bank1_miss"]= std::make_tuple("/sys/class/hwmon/hwmon0/l3cachehalf0/%s4",  0, "0x1a");
  g_dpu_stats.counters["l3_half1_bank0_hit"]= std::make_tuple("/sys/class/hwmon/hwmon0/l3cachehalf1/%s1",  0, "0x17");
  g_dpu_stats.counters["l3_half1_bank1_hit"]= std::make_tuple("/sys/class/hwmon/hwmon0/l3cachehalf1/%s2",  0, "0x18");
  g_dpu_stats.counters["l3_half1_bank0_miss"]= std::make_tuple( "/sys/class/hwmon/hwmon0/l3cachehalf1/%s3", 0, "0x19");
  g_dpu_stats.counters["l3_half1_bank1_miss"]= std::make_tuple("/sys/class/hwmon/hwmon0/l3cachehalf1/%s4",  0, "0x1a");
  for(int i = 0; i < THREADS_COUNT; ++i) {
    g_dpu_stats.per_thread_stats[i].memory_reads= 0;
    g_dpu_stats.per_thread_stats[i].memory_writes= 0;
  }
}

void
start_dpu_global_counters()
{

  FILE *fptr;
  for(auto& pair: g_dpu_stats.counters){
    char buffer[200];
    auto& file_counter_event = pair.second;
    snprintf(buffer, 200, std::get<0>(file_counter_event).c_str(), "event");
    open_file(buffer, &fptr, "w");
    fprintf(fptr, std::get<2>(file_counter_event).c_str());
    fclose(fptr);
  }

  open_file("/sys/class/hwmon/hwmon0/l3cachehalf0/enable", &fptr, "w");
  fprintf(fptr, "1");
  fclose(fptr);
  open_file("/sys/class/hwmon/hwmon0/l3cachehalf1/enable", &fptr, "w");
  fprintf(fptr, "1");
  fclose(fptr);

  for(auto& pair: g_dpu_stats.counters){
    char buffer[200];
    auto& file_counter_event = pair.second;

    snprintf(buffer, 200, std::get<0>(file_counter_event).c_str(), "counter");
    read_dpu_counter_file(buffer, &std::get<1>(file_counter_event));
  }
}

void
update_dpu_global_counters()
{
  for(auto& pair: g_dpu_stats.counters){

    uint64_t counter_read =0;

    char buffer[200];
    auto& file_counter_event = pair.second;
    snprintf(buffer, 200, std::get<0>(file_counter_event).c_str(), "counter");

    read_dpu_counter_file(buffer, &counter_read);
    std::get<1>(file_counter_event) = counter_read - std::get<1>(file_counter_event);
  }
}

void
start_dpu_thread_counters(uint8_t thread_id)
{
  FILE *fptr;
  open_file(("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) + "/event0").c_str(), &fptr, "w");
  fprintf(fptr, "0x4c");
  fclose(fptr);
  
  open_file(("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) + "/event1").c_str(), &fptr, "w");
  fprintf(fptr, "0x4d");
  fclose(fptr);

  read_dpu_counter_file("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) +"/counter0", &g_dpu_stats.per_thread_stats[thread_id].memory_reads);
  read_dpu_counter_file("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) +"/counter1", &g_dpu_stats.per_thread_stats[thread_id].memory_writes);
}

void
update_dpu_thread_counters(uint8_t thread_id)
{
  uint64_t memory_reads;
  uint64_t memory_writes;
  read_dpu_counter_file("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) +"/counter0", &memory_reads);
  read_dpu_counter_file("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) +"/counter1", &memory_writes);

  g_dpu_stats.per_thread_stats[thread_id].memory_reads = memory_reads - g_dpu_stats.per_thread_stats[thread_id].memory_reads;
  g_dpu_stats.per_thread_stats[thread_id].memory_writes = memory_writes - g_dpu_stats.per_thread_stats[thread_id].memory_writes;
}

