/* omawslogs.c
 *
 * This is an experimental output plugin to write logs to AWS CloudWatch Logs.
 *
 * Copyright 2018 Martin Schütte <info@mschuette.name>.
 *
 * Contributed to rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "cfsysline.h"
#include "module-template.h"
#include "errmsg.h"
#include "datetime.h"
#include "glbl.h"
#include "parserif.h"

#include "awslib.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omawslogs")

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(glbl)
DEFobjCurrIf(datetime)

typedef struct _instanceData {
    char *logGroup;
    char *logStream;
    char *awsRegion;
    struct awslib_instance *awslib_inst;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;

typedef struct configSettings_s {
    char *logGroup;
    char *logStream;
    char *awsRegion;
} configSettings_t;
static configSettings_t cs;

/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "group",    eCmdHdlrGetWord, 0 },
	{ "stream",   eCmdHdlrGetWord, 0 },
	{ "region",   eCmdHdlrGetWord, 0 },
    { "template", eCmdHdlrGetWord, 0 }
};
static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};



BEGINinitConfVars		/* (re)set config variables to default values */
CODESTARTinitConfVars
	cs.logGroup = NULL;
	cs.logStream = NULL;
	cs.awsRegion = NULL;
ENDinitConfVars

/* forward definitions (as few as possible) */
// TODO

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance


BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
    dbgprintf("awslogs");
    dbgprintf("\tregion='%s'\n", pData->awsRegion);
    dbgprintf("\tgroup='%s'\n",  pData->logGroup);
    dbgprintf("\tstream='%s'\n", pData->logStream);
ENDdbgPrintInstInfo

BEGINtryResume
    CODESTARTtryResume
    DBGPRINTF("omawslogs: tryResume called\n");
    iRet = RS_RET_OK;
ENDtryResume


BEGINdoAction
	const instanceData *const __restrict__ pData = pWrkrData->pData;
	char* toWrite;
	uint len;
CODESTARTdoAction
	toWrite = (char*) ppString[0];
	len = strlen(toWrite);

    DBGPRINTF("omawslogs doAction([%d] %s, %s, %s, %s)\n",
			  len, toWrite, pData->awsRegion, pData->logGroup, pData->logStream);
    iRet = aws_logs_msg_put(pData->awslib_inst, pData->logGroup, pData->logStream, (const char *) ppString[0]);

	if(iRet == RS_RET_OK) {
        DBGPRINTF("sent something\n");
    } else {
        DBGPRINTF("error sending to awslogs\n");
	}
ENDdoAction


BEGINnewActInst
	struct cnfparamvals *pvals;
	int rc;
CODESTARTnewActInst
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(createInstance(&pData));

    for(int i = 0 ; i < actpblk.nParams ; ++i) {
        if(!pvals[i].bUsed)
            continue;
        if(!strcmp(actpblk.descr[i].name, "region")) {
            pData->awsRegion = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(actpblk.descr[i].name, "group")) {
            pData->logGroup  = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(actpblk.descr[i].name, "stream")) {
            pData->logStream = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else {
            DBGPRINTF("omawslogs: program error, non-handled "
                      "param '%s'\n", actpblk.descr[i].name);
        }
    }

    /* like setInstParamDefaults, but only if no user params present */
	if (!pData->logGroup) {
		pData->logGroup = "rsyslog";
	}
    if (!pData->logStream) {
        if((pData->logStream = calloc(1, HOST_NAME_MAX)) == NULL) {
            return RS_RET_OUT_OF_MEMORY;
        }
        gethostname(pData->logStream, HOST_NAME_MAX);
    }

    CODE_STD_STRING_REQUESTnewActInst(1)
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar*)strdup("RSYSLOG_FileFormat"),
						 OMSR_NO_RQD_TPL_OPTS));

    pData->awslib_inst = aws_init(pData->awsRegion);
	rc = aws_logs_ensure(pData->awslib_inst, pData->logGroup, pData->logStream);
	if (rc) {
        DBGPRINTF("omawslogs: program error, aws_logs_ensure returned %d with msg '%s'\n",
                rc, pData->awslib_inst->last_error_message);
        ABORT_FINALIZE(RS_RET_DATAFAIL);
	} else {
        DBGPRINTF("omawslogs: aws_logs_ensure successful\n");
	}

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


NO_LEGACY_CONF_parseSelectorAct


/* Free string config variables and reset them to NULL (not necessarily the default!) */
static rsRetVal freeConfigVariables(void)
{
	DEFiRet;

    cs.awsRegion = NULL;
    cs.logGroup = NULL;
    cs.logStream = NULL;

	RETiRet;
}


BEGINmodExit
CODESTARTmodExit
	/* cleanup our allocations */
	freeConfigVariables();

	/* release what we no longer need */
	objRelease(datetime, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_CNFNAME_QUERIES
ENDqueryEtryPt


/* Reset config variables for this module to default values.
 */
static rsRetVal resetConfigVariables(uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal)
{
	DEFiRet;
	iRet = freeConfigVariables();
	RETiRet;
}


BEGINmodInit()
CODESTARTmodInit
INITLegCnfVars
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	/* tell which objects we need */
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));

	DBGPRINTF("omawslogs version %s initializing\n", VERSION);

	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "actionawsloggroup",    0, eCmdHdlrGetWord, NULL, &cs.logGroup,   STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "actionawslogstream",   0, eCmdHdlrGetWord, NULL, &cs.logStream,  STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "actionawsregion",      0, eCmdHdlrGetWord, NULL, &cs.awsRegion, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "resetconfigvariables", 1, eCmdHdlrCustomHandler, resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));
ENDmodInit
