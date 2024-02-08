#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>

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
  uint64_t memory_read;
  uint64_t memory_write;
  uint64_t reads_difference;
  uint64_t writes_difference;
} dpu_statistics[THREADS_COUNT];

// This structure is returned each time the main measurement is read.
// It contains the result of all the measurements, taken simultaneously.
// The order of the measurements is unknown - used the ID.
#define EVENTS_MEASURED 2
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

  // Create a measurement using hardware (CPU) registers. Measure the number of instructions amassed.
  measure_l1_read_hit = perf_create_measurement(PERF_TYPE_HW_CACHE, 
                                            (PERF_COUNT_HW_CACHE_L1D | PERF_COUNT_HW_CACHE_OP_READ<<8 | PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
                                            0,
                                            -1);
  prepare_measurement("l1_read_hit", measure_l1_read_hit, NULL);

  measure_l1_read_miss = perf_create_measurement(PERF_TYPE_HW_CACHE, 
                                            (PERF_COUNT_HW_CACHE_L1D | PERF_COUNT_HW_CACHE_OP_READ<<8 | PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                                            0,
                                            -1);
  // This might be the cause for overcounting the events, the l1 misses are bound to l1 read hits
  prepare_measurement("l1_read_miss", measure_l1_read_miss, measure_l1_read_hit);
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
}

static dpu_statistics g_dpu_stats = 
 {
    {0, 0,   0, 0},
    {0, 0,   0, 0},
    {0, 0, 0, 0},
    {0, 0, 0, 0},
    {0, 0,   0, 0},
    {0, 0,   0, 0},
    {0, 0, 0, 0},
    {0, 0, 0, 0},
};
void print_dpu_measurements(std::ostringstream &result) {
  for(uint8_t thr=0; thr<THREADS_COUNT; ++thr) {
    result<<" \"thread"<<int(thr)<<"\":"<<" {";
    result<< "\"memory_read\":\"" <<g_dpu_stats[thr].reads_difference << "\",\t"
          << "\"memory_writes\":\"" << g_dpu_stats[thr].writes_difference << "\" \t";
    result<<" },"<<'\t';
  }
}

void print_perf_measurements(std::ostringstream &result, measurement_t *measurement) {
    uint64_t values[EVENTS_MEASURED] = {0};
    // perf_measurement_t *taken_measurements[] = {all_measurements, measure_instruction_count, measure_cycle_count, measure_context_switches, measure_cpu_clock, measure_cpu_branches, measure_l1_read_hit};

    perf_measurement_t *taken_measurements[] = {measure_l1_read_hit, measure_l1_read_miss};
    for (uint64_t j = 0; j < measurement->recorded_values; j++) {
      for (int k = 0; k < EVENTS_MEASURED; k++) {
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
    result<<" \"l1_read_hit\":\""<<values[0]<< "\",\t"
          <<" \"l1_read_miss\":\""<<values[1]<< "\",\t";
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
open_file(char *fname, FILE **file)
{
    // char fname[100];
    // sprintf(fname, "/tmp/build/stats%d", test_num);
    *file = fopen(fname, "r");

    if(*file == NULL)
    {
      return BAD_STATE;
    }
  return SUCCESS;
}


int
read_hw_counters(std::string fname, uint64_t *counter)
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
update_dpu_counters(uint8_t thread_id)
{
  uint64_t memory_read;
  uint64_t memory_write;
  
  read_hw_counters("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) +"/counter0", &memory_read);
  read_hw_counters("/sys/class/hwmon/hwmon0/tile"+std::to_string(thread_id/2) +"/counter1", &memory_write);
  g_dpu_stats[thread_id].reads_difference = memory_read - g_dpu_stats[thread_id].memory_read;
  g_dpu_stats[thread_id].memory_read = memory_read;
  g_dpu_stats[thread_id].writes_difference = memory_write - g_dpu_stats[thread_id].memory_write;
  g_dpu_stats[thread_id].memory_write = memory_write;
}

