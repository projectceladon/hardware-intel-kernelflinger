/******************************************************************************
 *
 * INTEL CONFIDENTIAL
 *
 * Copyright (c) 2017 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to
 * the source code (Material) are owned by Intel Corporation or its suppliers
 * or licensors. Title to the Material remains with Intel Corporation or its
 * suppliers and licensors. The Material contains trade secrets and proprietary
 * and confidential information of Intel or its suppliers and licensors. The
 * Material is protected by worldwide copyright and trade secret laws and
 * treaty provisions. No part of the Material may be used, copied, reproduced,
 * modified, published, uploaded, posted, transmitted, distributed, or
 * disclosed in any way without Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by Intel in writing.
 *
 ******************************************************************************/

#ifndef _HECISUPPORT_H_
#define _HECISUPPORT_H_

#include "../../libkernelflinger/protocol/Heci.h"
#include "../../libkernelflinger/protocol/MkhiMsgs.h"

#define EOP_GROUP_ID 0xFF
#define EOP_CMD_ID   0xC

//EOP-REQ
typedef struct _GEN_END_OF_POST
{
	MKHI_MESSAGE_HEADER  MKHIHeader;
} GEN_END_OF_POST;

extern EFI_STATUS heci_end_of_post(void);

#endif   /*  _HECISUPPORT_H_  */
