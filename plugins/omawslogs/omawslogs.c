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
    CloudWatchLogsController *ctl;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;

typedef struct configSettings_s {
    char *log_group;
    char *log_stream;
    char *aws_region;
    // TODO: add template?
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
	cs.log_group = NULL;
	cs.log_stream = NULL;
	cs.aws_region = NULL;
ENDinitConfVars


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
    dbgprintf("\tcontroller='%p'\n", pData->ctl);
ENDdbgPrintInstInfo


BEGINtryResume
    CODESTARTtryResume
    DBGPRINTF("omawslogs: tryResume called\n");
    iRet = RS_RET_OK;
ENDtryResume


BEGINdoAction
	const instanceData *const __restrict__ pData = pWrkrData->pData;
	CloudWatchLogsController *ctl = pData->ctl;
	char* toWrite;
	uint len;
CODESTARTdoAction
	toWrite = (char*) ppString[0];
	len = strlen(toWrite);

    DBGPRINTF("omawslogs doAction([%d] %s, %p)\n",
			  len, toWrite, ctl);
    iRet = aws_logs_msg_put(ctl, (const char *) ppString[0]);

	if(iRet == RS_RET_OK) {
        DBGPRINTF("sent something\n");
    } else {
        DBGPRINTF("error sending to awslogs\n");
	}
ENDdoAction


BEGINnewActInst
	struct cnfparamvals *pvals;
	int rc;
	char *region = NULL;
	char *group = NULL;
	char *stream = NULL;
CODESTARTnewActInst
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(createInstance(&pData));

    for(int i = 0 ; i < actpblk.nParams ; ++i) {
        if(!pvals[i].bUsed)
            continue;
        if(!strcmp(actpblk.descr[i].name, "region")) {
            region = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(actpblk.descr[i].name, "group")) {
            group  = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(actpblk.descr[i].name, "stream")) {
            stream = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else {
            DBGPRINTF("omawslogs: program error, non-handled "
                      "param '%s'\n", actpblk.descr[i].name);
        }
    }

    CODE_STD_STRING_REQUESTnewActInst(1)
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar*)strdup("RSYSLOG_FileFormat"),
						 OMSR_NO_RQD_TPL_OPTS));

    pData->ctl = aws_init(region, group, stream);
    rc = aws_logs_ensure(pData->ctl);

	if (rc) {
        DBGPRINTF("omawslogs: program error, aws_logs_ensure returned %d with msg '%s'\n",
                rc, aws_logs_get_last_error(pData->ctl));
        ABORT_FINALIZE(RS_RET_DATAFAIL);
	} else {
        DBGPRINTF("omawslogs: aws_logs_ensure successful\n");
	}

	// TODO: can we avoid the es_str2cstr() and free() for params?
    free(region);
    free(group);
    free(stream);
CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


NO_LEGACY_CONF_parseSelectorAct


/* Free string config variables and reset them to NULL (not necessarily the default!) */
static rsRetVal freeConfigVariables(void)
{
	DEFiRet;

    free(cs.aws_region);
    cs.aws_region = NULL;
    free(cs.log_group);
    cs.log_group = NULL;
    free(cs.log_stream);
    cs.log_stream = NULL;

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

	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "actionawsloggroup",    0, eCmdHdlrGetWord, NULL, &cs.log_group,   STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "actionawslogstream",   0, eCmdHdlrGetWord, NULL, &cs.log_stream,  STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "actionawsregion",      0, eCmdHdlrGetWord, NULL, &cs.aws_region, STD_LOADABLE_MODULE_ID));
	CHKiRet(omsdRegCFSLineHdlr(	(uchar*) "resetconfigvariables", 1, eCmdHdlrCustomHandler, resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));
ENDmodInit
