//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2013-2016 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include <stdlib.h>

#include "pal.h"
#include "pal_BSP.h"

#include "unity_fixture.h"
#include "cose_test_runner.h"

#include "mbed-trace/mbed_trace.h"
#include "mbed-trace-helper.h"


#define TRACE_GROUP     "cose"  // Maximum 4 characters

extern bool dhcp_done;
static int g_unity_status = EXIT_FAILURE;
static pal_args_t g_args = { 0 };


/**
*
* Runs all tests in a task of its own
*/
static void run_cose_component_tests_task(pal_args_t *args)
{
    int rc = 0;
    bool success = 0;
    uint8_t activated_level = 0;
    palStatus_t pal_status;
    bool is_mutex_used = false;

    int myargc = args->argc + 2;
    const char **myargv = (const char **)calloc(myargc, sizeof(char *));
    if (myargv == NULL) {
        goto cleanup;
    }
    myargv[0] = "cose_component_tests";
    myargv[1] = "-v";
    for (int i = 0; i < args->argc; i++) {
        myargv[i + 2] = args->argv[i];
    }

    // Initialize PAL
    pal_status = pal_init();
    if (pal_status != PAL_SUCCESS) {
        goto cleanup;
    }

    //Initialize mbed-trace
    success = mbed_trace_helper_init(TRACE_ACTIVE_LEVEL_ALL, is_mutex_used);
    if (success != true) {
        goto cleanup;
    }

    setvbuf(stdout, (char *)NULL, _IONBF, 0); /* Avoid buffering on test output */
    tr_info("cose_component_tests: Starting component tests...\n");

    // Wait until device is connected to the world
    while (dhcp_done == 0) {
        pal_osDelay(500);
    }
    
    tr_cmdline("----< Test - Start >----\n");
    rc = UnityMain(myargc, myargv, RunAllCoseTests);
    tr_cmdline("----< Test - End >----\n");

    if (rc > 0) {
        tr_error("cose_component_tests: Test failed.\n");
    } else {
        g_unity_status = EXIT_SUCCESS;
        tr_info("cose_component_tests: Test passed.\n");
    }

cleanup:
    // This is detected by test runner app, so that it can know when to terminate without waiting for timeout.
    tr_cmdline("***END OF TESTS**\n");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    mbed_trace_helper_finish();
    pal_destroy();
    free(myargv);
    fflush(stdout);
}

int main(int argc, char * argv[])
{
    bool success = 0;

    // Do not use argc/argv as those are not initialized
    // for armcc and may cause allocation failure.
    (void)argc;
    (void)argv;

    g_args.argc = 0;
    g_args.argv = NULL;

    success = initPlatform();
    if (success) {
        success = runProgram(&run_cose_component_tests_task, &g_args);
    }

    return success ? g_unity_status : EXIT_FAILURE;
}
