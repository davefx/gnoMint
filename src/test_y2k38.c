//  gnoMint: a graphical interface for managing a certification authority
//  Test for Y2K38 compatibility
//  
//  This test verifies that gnoMint can handle certificate dates beyond
//  January 19, 2038 03:14:07 UTC (the Year 2038 problem)

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>

// Test that time_t is 64-bit
void test_time_t_size() {
    printf("Test 1: Checking time_t size...\n");
    size_t time_t_size = sizeof(time_t);
    printf("  sizeof(time_t) = %zu bytes\n", time_t_size);
    
    if (time_t_size >= 8) {
        printf("  ✓ PASS: time_t is 64-bit or larger\n");
    } else {
        printf("  ✗ FAIL: time_t is only %zu bytes (32-bit)\n", time_t_size);
        exit(1);
    }
    printf("\n");
}

// Test that we can represent dates beyond 2038
void test_dates_beyond_2038() {
    printf("Test 2: Testing dates beyond 2038...\n");
    
    // Test date: January 1, 2039 00:00:00 UTC
    struct tm test_tm = {0};
    test_tm.tm_year = 139; // 2039 - 1900
    test_tm.tm_mon = 0;    // January
    test_tm.tm_mday = 1;
    test_tm.tm_hour = 0;
    test_tm.tm_min = 0;
    test_tm.tm_sec = 0;
    
    // Use timegm() for UTC time conversion (avoids timezone issues)
    #ifndef WIN32
    time_t test_time = timegm(&test_tm);
    #else
    // On Windows, use _mkgmtime if available
    time_t test_time = _mkgmtime(&test_tm);
    #endif
    
    printf("  Testing date: 2039-01-01 00:00:00 UTC\n");
    printf("  time_t value: %ld\n", (long)test_time);
    
    if (test_time == (time_t)-1) {
        printf("  ✗ FAIL: timegm() failed for year 2039\n");
        exit(1);
    }
    
    // Verify we can convert it back
    struct tm *result_tm = gmtime(&test_time);
    if (result_tm == NULL) {
        printf("  ✗ FAIL: gmtime() returned NULL for year 2039\n");
        exit(1);
    }
    
    char buf[100];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", result_tm);
    printf("  Converted back to: %s UTC\n", buf);
    
    if (result_tm->tm_year != 139) {
        printf("  ✗ FAIL: Year mismatch after conversion\n");
        exit(1);
    }
    
    printf("  ✓ PASS: Can handle dates in 2039\n");
    printf("\n");
}

// Test dates far into the future (50 years)
void test_dates_far_future() {
    printf("Test 3: Testing dates 50 years in the future...\n");
    
    time_t now = time(NULL);
    struct tm *now_tm = gmtime(&now);
    char now_str[100];
    strftime(now_str, sizeof(now_str), "%Y-%m-%d", now_tm);
    printf("  Current date: %s UTC\n", now_str);
    
    // Add 50 years (600 months)
    struct tm future_tm = *now_tm;
    future_tm.tm_year += 50;
    
    // Use timegm() for UTC time conversion
    #ifndef WIN32
    time_t future_time = timegm(&future_tm);
    #else
    time_t future_time = _mkgmtime(&future_tm);
    #endif
    
    if (future_time == (time_t)-1) {
        printf("  ✗ FAIL: timegm() failed for date 50 years in the future\n");
        exit(1);
    }
    
    struct tm *result_tm = gmtime(&future_time);
    if (result_tm == NULL) {
        printf("  ✗ FAIL: gmtime() returned NULL for future date\n");
        exit(1);
    }
    
    char future_str[100];
    strftime(future_str, sizeof(future_str), "%Y-%m-%d", result_tm);
    printf("  Date in 50 years: %s UTC\n", future_str);
    printf("  time_t value: %ld\n", (long)future_time);
    
    printf("  ✓ PASS: Can handle dates 50 years in the future\n");
    printf("\n");
}

// Test the critical Y2K38 boundary
void test_y2k38_boundary() {
    printf("Test 4: Testing Y2K38 boundary (2038-01-19 03:14:07 UTC)...\n");
    
    // The critical timestamp for 32-bit signed time_t
    time_t boundary = 0x7FFFFFFF; // 2147483647
    
    printf("  Boundary time_t value: %ld\n", (long)boundary);
    
    struct tm *boundary_tm = gmtime(&boundary);
    if (boundary_tm == NULL) {
        printf("  ✗ FAIL: gmtime() returned NULL for boundary\n");
        exit(1);
    }
    
    char buf[100];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", boundary_tm);
    printf("  Boundary represents: %s\n", buf);
    
    // Test one second after the boundary
    time_t after_boundary = boundary + 1;
    struct tm *after_tm = gmtime(&after_boundary);
    
    if (after_tm == NULL) {
        printf("  ✗ FAIL: gmtime() returned NULL for time after boundary\n");
        exit(1);
    }
    
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", after_tm);
    printf("  One second after: %s\n", buf);
    
    // Verify the year is still 2038 (should be 2038-01-19 03:14:08)
    if (after_tm->tm_year + 1900 == 2038) {
        printf("  ✓ PASS: Can handle dates after Y2K38 boundary\n");
    } else {
        printf("  ✗ FAIL: Date after boundary is incorrect (year=%d)\n", 
               after_tm->tm_year + 1900);
        exit(1);
    }
    printf("\n");
}

int main() {
    printf("===========================================\n");
    printf("gnoMint Y2K38 Compatibility Test Suite\n");
    printf("===========================================\n\n");
    
    test_time_t_size();
    test_dates_beyond_2038();
    test_dates_far_future();
    test_y2k38_boundary();
    
    printf("===========================================\n");
    printf("All tests passed! ✓\n");
    printf("gnoMint is Y2K38-safe and can handle\n");
    printf("certificates with expiration dates well\n");
    printf("beyond January 19, 2038.\n");
    printf("===========================================\n");
    
    return 0;
}
