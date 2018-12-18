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

#include <rsyslog_awslogs.h>

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omawslogs")

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(glbl)
DEFobjCurrIf(datetime)

typedef struct _instanceData {
	char *region;
	char *group;
	char *stream;
	char *template;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
	CloudWatchLogsController *ctl;
} wrkrInstanceData_t;

/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "region",   eCmdHdlrGetWord, 0 },
	{ "group",    eCmdHdlrGetWord, 0 },
	{ "stream",   eCmdHdlrGetWord, 0 },
	{ "template", eCmdHdlrGetWord, 0 }
};
static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};


BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance


BEGINcreateWrkrInstance
    int rc;
CODESTARTcreateWrkrInstance
	DBGPRINTF("omawslogs: createWrkrInstance\n");

	pWrkrData->ctl = aws_init(pData->region, pData->group, pData->stream);
	rc = aws_logs_ensure(pWrkrData->ctl);

	if (rc) {
		DBGPRINTF("omawslogs: program error, aws_logs_ensure returned %d with msg '%s'\n",
		          rc, aws_logs_get_last_error(pWrkrData->ctl));
		iRet = RS_RET_DATAFAIL;
	} else {
		DBGPRINTF("omawslogs: aws_logs_ensure successful\n");
	}
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
	if (pData->region) {
		free(pData->region);
		pData->region = NULL;
	}
	if (pData->group) {
		free(pData->group);
		pData->group = NULL;
	}
	if (pData->stream) {
		free(pData->stream);
		pData->stream = NULL;
	}
	if (pData->template) {
		free(pData->template);
		pData->template = NULL;
	}
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
	aws_shutdown(pWrkrData->ctl);
ENDfreeWrkrInstance


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	dbgprintf("awslogs");
	dbgprintf("\tregion='%p'\n", pData->region);
	dbgprintf("\tgroup='%p'\n", pData->group);
	dbgprintf("\tstream='%p'\n", pData->stream);
	dbgprintf("\ttemplate='%p'\n", pData->template);
ENDdbgPrintInstInfo


BEGINtryResume
	CODESTARTtryResume
	DBGPRINTF("omawslogs: tryResume called\n");
	iRet = RS_RET_OK;
ENDtryResume


BEGINdoAction
	CloudWatchLogsController *ctl = pWrkrData->ctl;
	CODESTARTdoAction
	DBGPRINTF("omawslogs doAction([%zu] %s, %p)\n",
	          strlen((char *) ppString[0]), (char *) ppString[0], ctl);
	iRet = aws_logs_msg_put(ctl, (const char *) ppString[0]);

	if(iRet == RS_RET_OK) {
		DBGPRINTF("sent something\n");
	} else {
		DBGPRINTF("error sending to awslogs: %s\n", aws_logs_get_last_error(ctl));
	}
ENDdoAction


BEGINnewActInst
	struct cnfparamvals *pvals;
CODESTARTnewActInst
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(createInstance(&pData));

	for(int i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(actpblk.descr[i].name, "region")) {
			pData->region = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "group")) {
			pData->group  = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "stream")) {
			pData->stream = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "template")) {
			pData->template = es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			DBGPRINTF("omawslogs: program error, non-handled "
			          "param '%s'\n", actpblk.descr[i].name);
		}
	}

	CODE_STD_STRING_REQUESTnewActInst(1)
	if (!pData->template) {
		pData->template = strdup("RSYSLOG_FileFormat");
	}
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar*) pData->template, OMSR_NO_RQD_TPL_OPTS));

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


NO_LEGACY_CONF_parseSelectorAct


BEGINmodExit
CODESTARTmodExit
	/* release what we no longer need */
	objRelease(datetime, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	/* tell which objects we need */
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));

	DBGPRINTF("omawslogs version %s initializing\n", VERSION);
ENDmodInit
