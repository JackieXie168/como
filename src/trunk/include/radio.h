/*
 * Copyright (c) 2006 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#ifndef RADIO_H_
#define RADIO_H_

#include "nettypes.h"

enum RADIO_PHYTYPE {
    RADIO_PHYTYPE_NONE =                0,
    RADIO_PHYTYPE_FHSS_DOT11_97 =	1,
    RADIO_PHYTYPE_DSSS_DOT11_97 =	2,
    RADIO_PHYTYPE_IRBASEBAND =		3,
    RADIO_PHYTYPE_DSSS_DOT11_B =	4,
    RADIO_PHYTYPE_PBCC_DOT11_B =	5,
    RADIO_PHYTYPE_OFDM_DOT11_G =	6,
    RADIO_PHYTYPE_PBCC_DOT11_G =	7,
    RADIO_PHYTYPE_OFDM_DOT11_A =	8,
    RADIO_PHYTYPE_DSSS_OFDM_DOT11_G =	9
};

enum RADIO_SSITYPE {
    RADIO_SSITYPE_NONE =		0,
    RADIO_SSITYPE_NORMALIZED_RSSI =	1,
    RADIO_SSITYPE_DBM =			2,
    RADIO_SSITYPE_RAW_RSSI =		3
};

enum RADIO_PREAMBLE {
    RADIO_PREAMBLE_UNDEFINED =		0,
    RADIO_PREAMBLE_SHORT_PREAMBLE =	1,
    RADIO_PREAMBLE_LONG_PREAMBLE =	2
};

enum RADIO_ENCODING {
    RADIO_ENCODING_UNKNOWN =		0,
    RADIO_ENCODING_CCK =		1,
    RADIO_ENCODING_PBCC =		2,
    RADIO_ENCODING_OFDM =		3,
    RADIO_ENCODING_DSSS_OFDM =		4
};
	
struct _como_radio {
    n64_t mactime;	/* Many WLAN devices supply a relatively high
			 * resolution frame reception time value.  This field
			 * contains the value supplied by the device.  If the
			 * device does not supply a receive time value, this
			 * field shall be set to zero. The units for this
			 * field are nanoseconds.
			 */
    n64_t hosttime;	/* The hosttime field is set to the current value of
			 * the host maintained clock variable when the frame is
			 * received.
			 */
    n32_t phytype;	/* The phytype field identifies what type of PHY is
			 * employed by the WLAN device used to capture this
			 * frame. The valid values are RADIO_PHYTYPE_*.
			 */
    n32_t channel;	/* For all PHY types except FH, this field is just an
			 * unsigned integer and will be set to the current
			 * receiver channel number at the time the frame was
			 * received.  For frequency hopping radios, this field 
			 * is broken in to the following subfields:
			 * Byte    Subfield
			 * ------------------------
			 * Byte0   Hop Set
			 * Byte1   Hop Pattern
			 * Byte2   Hop Index
			 * Byte3   reserved
			 */
    n32_t datarate;	/* The data rate field contains the rate at which the
			 * frame was received in units of 100kbps.
			 */
    n32_t antenna;	/* For WLAN devices that indicate the receive antenna
			 * for each frame, the antenna field shall contain an
			 * index value into the dot11AntennaList.
			 * If the device does not indicate a receive antenna
			 * value, this field shall be set to zero.
			 */
    n32_t priority;	/* The priority field indicates the receive priority of
			 * the frame.  The value is in the range [0-15] with
			 * the value 0 reserved to indicate contention period
			 * and the value 6 reserved to indicate contention free
			 * period.
			 */
    n32_t ssitype;	/* The ssitype field is used to indicate what type of
			 * signal strength information is present: "None",
			 * "Normalized RSSI" or "dBm".  "None" indicates that
			 * the underlying WLAN device does not supply any
			 * signal strength at all and the ssi_* values are
			 * unset.  "Normalized RSSI" values are integers in
			 * the range [0-1000] where higher numbers indicate
			 * stronger signal.  "dBm" values indicate an actual
			 * signal strength measurement quantity and are
			 * usually in the range [-108 - 10].
			 * The valid values are RADIO_SSITYPE_*.
			 */
    n32_t ssisignal;	/* The ssisignal field contains the signal strength
			 * value reported by the WLAN device for this frame.
			 * Note that this is a signed quantity and if the
			 * ssitype value is "dBm" that the value may be
			 * negative.
			 */
    n32_t ssinoise;	/* The ssinoise field contains the noise or "silence"
			 * value reported by the WLAN device.  This value is
			 * commonly defined to be the "signal strength
			 * reported immediately prior to the baseband
			 * processor lock on the frame preamble". If the
			 * hardware does not provide noise data, this shall
			 * equal 0xffffffff.
			 */
    n32_t preamble;	/* For PHYs that support variable preamble lengths,
			 * the preamble field indicates the preamble type used
			 * for this frame. The values are RADIO_PREAMBLE_*.
			 */
    n32_t encoding;	/* This specifies the encoding of the received packet.
			 * For PHYs that support multiple encoding types, this
			 * will tell us which one was used.
			 */
};

#define RADIO(field)						\
    (((struct _como_radio*) (pkt->payload))->field)

#endif /*RADIO_H_*/
