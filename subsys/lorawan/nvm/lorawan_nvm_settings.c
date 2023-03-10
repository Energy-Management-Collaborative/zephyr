/*
 * Copyright (c) 2022 Intellinium <giuliano.franchetto@intellinium.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <LoRaMac.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>
#include "lorawan_nvm.h"
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lorawan_nvm, CONFIG_LORAWAN_LOG_LEVEL);

#define LORAWAN_SETTINGS_BASE                "lorawan/nvm"

struct lorawan_nvm_setting_descr {
	const char *name;
	const char *setting_name;
	size_t size;
	off_t offset;
	uint16_t flag;
};

#define NVM_SETTING_DESCR(_flag, _member) \
	{									\
		.flag = _flag,							\
		.name = STRINGIFY(_member),					\
		.setting_name =						\
			LORAWAN_SETTINGS_BASE "/" STRINGIFY(_member),		\
		.offset = offsetof(LoRaMacNvmData_t, _member),		\
		.size = sizeof(((LoRaMacNvmData_t *)0)->_member),		\
	}

static const struct lorawan_nvm_setting_descr nvm_setting_descriptors[] = {
	NVM_SETTING_DESCR(LORAMAC_NVM_NOTIFY_FLAG_CRYPTO, Crypto),
	NVM_SETTING_DESCR(LORAMAC_NVM_NOTIFY_FLAG_MAC_GROUP1, MacGroup1),
	NVM_SETTING_DESCR(LORAMAC_NVM_NOTIFY_FLAG_MAC_GROUP2, MacGroup2),
	NVM_SETTING_DESCR(LORAMAC_NVM_NOTIFY_FLAG_SECURE_ELEMENT, SecureElement),
	NVM_SETTING_DESCR(LORAMAC_NVM_NOTIFY_FLAG_REGION_GROUP1, RegionGroup1),
	NVM_SETTING_DESCR(LORAMAC_NVM_NOTIFY_FLAG_REGION_GROUP2, RegionGroup2),
	NVM_SETTING_DESCR(LORAMAC_NVM_NOTIFY_FLAG_CLASS_B, ClassB),
};

static void lorawan_nvm_save_settings(uint16_t nvm_notify_flag)
{
	MibRequestConfirm_t mib_req;

	LOG_DBG("Saving LoRaWAN settings");

	/* Retrieve the actual context */
	mib_req.Type = MIB_NVM_CTXS;
	if (LoRaMacMibGetRequestConfirm(&mib_req) != LORAMAC_STATUS_OK) {
		LOG_ERR("Could not get NVM context");
		return;
	}

	LoRaMacNvmData_t *nvm = mib_req.Param.Contexts;

	/**
	 * Normally, this would persist data after every tx/rx event.
	 * That's way too frequent for our desired flash longevity,
	 * so limit it to when DevNonce changes (or a few times per day)
	 */
	const int HOUR = 60 * 60 * 1000;
	static uint16_t last_dev_nonce = 0;
	static int64_t last_saved_at = 0;
	int delay_til_next_save = (6 * HOUR) - (k_uptime_get() - last_saved_at);

	if (last_dev_nonce == mib_req.Param.Contexts->Crypto.DevNonce && delay_til_next_save > 0) {
		LOG_DBG("Skipping for %d seconds", delay_til_next_save / 1000);
		return;
	}

	last_dev_nonce = mib_req.Param.Contexts->Crypto.DevNonce;
	last_saved_at = k_uptime_get();

	LOG_DBG("Crypto version: %"PRIu32", DevNonce: %d, JoinNonce: %"PRIu32,
		mib_req.Param.Contexts->Crypto.LrWanVersion.Value,
		mib_req.Param.Contexts->Crypto.DevNonce,
		mib_req.Param.Contexts->Crypto.JoinNonce);

	for (uint32_t i = 0; i < ARRAY_SIZE(nvm_setting_descriptors); i++) {
		const struct lorawan_nvm_setting_descr *descr =
			&nvm_setting_descriptors[i];

		if ((nvm_notify_flag & descr->flag) == descr->flag) {
			LOG_DBG("Saving configuration %s", descr->setting_name);
			int err = settings_save_one(descr->setting_name,
						(char *)nvm + descr->offset,
						descr->size);
			if (err) {
				LOG_ERR("Could not save settings %s, error %d",
					descr->name, err);
			}
		}
	}

	settings_save();
}

void lorawan_nvm_data_mgmt_event(uint16_t flags)
{
	if (flags != LORAMAC_NVM_NOTIFY_FLAG_NONE) {
		lorawan_nvm_save_settings(flags);
	}
}

static int load_setting(void *tgt, size_t tgt_size,
			const char *key, size_t len,
			settings_read_cb read_cb, void *cb_arg)
{
	if (len != tgt_size) {
		LOG_ERR("Can't load '%s' state, size mismatch.",
			key);
		return -EINVAL;
	}

	if (!tgt) {
		LOG_ERR("Can't load '%s' state, no target.",
			key);
		return -EINVAL;
	}

	if (read_cb(cb_arg, tgt, len) != len) {
		LOG_ERR("Can't load '%s' state, short read.",
			key);
		return -EINVAL;
	}

	return 0;
}

static int on_setting_loaded(const char *key, size_t len,
			   settings_read_cb read_cb,
			   void *cb_arg, void *param)
{
	int err;
	LoRaMacNvmData_t *nvm = param;

	LOG_DBG("Key: %s", key);

	for (uint32_t i = 0; i < ARRAY_SIZE(nvm_setting_descriptors); i++) {
		const struct lorawan_nvm_setting_descr *descr =
			&nvm_setting_descriptors[i];

		if (strcmp(descr->name, key) == 0) {
			err = load_setting((char *)nvm + descr->offset,
				descr->size, key, len, read_cb, cb_arg);
			if (err) {
				LOG_ERR("Could not read setting %s", descr->name);
			}
			return err;
		}
	}

	LOG_WRN("Unknown LoRaWAN setting: %s", key);
	return 0;
}

int lorawan_nvm_data_restore(void)
{
	int err;
	LoRaMacStatus_t status;
	MibRequestConfirm_t mib_req;

	LOG_DBG("Restoring LoRaWAN settings");

	/* Retrieve the actual context */
	mib_req.Type = MIB_NVM_CTXS;
	if (LoRaMacMibGetRequestConfirm(&mib_req) != LORAMAC_STATUS_OK) {
		LOG_ERR("Could not get NVM context");
		return -EINVAL;
	}

	err = settings_load_subtree_direct(LORAWAN_SETTINGS_BASE,
					   on_setting_loaded,
					   mib_req.Param.Contexts);
	if (err) {
		LOG_ERR("Could not load LoRaWAN settings, error %d", err);
		return err;
	}

	LOG_DBG("Crypto version: %"PRIu32", DevNonce: %d, JoinNonce: %"PRIu32,
		mib_req.Param.Contexts->Crypto.LrWanVersion.Value,
		mib_req.Param.Contexts->Crypto.DevNonce,
		mib_req.Param.Contexts->Crypto.JoinNonce);

	mib_req.Type = MIB_NVM_CTXS;
	status = LoRaMacMibSetRequestConfirm(&mib_req);
	if (status != LORAMAC_STATUS_OK) {
		LOG_ERR("Could not set the NVM context, error %d", status);
		return -EINVAL;
	}

	LOG_DBG("LoRaWAN context restored");

	return 0;
}

int lorawan_nvm_init(void)
{
	return settings_subsys_init();
}
