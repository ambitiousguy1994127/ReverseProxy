#ifndef BENCHMARK_H
#define BENCHMARK_H

#define USES_BENCHMARK clock_t begin, end; double delta;
#define START_BENCHMARK(title) do { apr_file_printf(out, "starting benchmark \"%s\"\n", title); begin = clock(); } while (0);
#define STOP_BENCHMARK(count) do { end = clock(); delta = end - begin; apr_file_printf(out, "ticks=%f, time = %2.8f, total = %2.8f, count = %d\n", delta, delta/CLOCKS_PER_SEC/(count),  delta/CLOCKS_PER_SEC, count); } while (0);

#endif
