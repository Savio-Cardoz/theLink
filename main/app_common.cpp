#include <vector>

#include "app_common.hpp"

namespace app {

static IFileSystem *s_sdcard = nullptr;
static esp_mqtt_client_handle_t s_mqtt = nullptr;
static std::vector<ConnectCallback> s_on_connect;

IFileSystem *sdcard()
{
	return s_sdcard;
}

void set_sdcard(IFileSystem *fs)
{
	s_sdcard = fs;
}

esp_mqtt_client_handle_t mqtt()
{
	return s_mqtt;
}

void set_mqtt(esp_mqtt_client_handle_t client)
{
	s_mqtt = client;
}

bool mqtt_publish(const char *topic, const char *payload, int qos, int retain)
{
	if (s_mqtt == nullptr)
	{
		return false;
	}
	int msg_id = esp_mqtt_client_publish(s_mqtt, topic, payload, 0, qos, retain);
	return msg_id >= 0;
}

void register_on_connect(ConnectCallback cb)
{
	s_on_connect.push_back(std::move(cb));
}

void fire_on_connect()
{
	for (auto &cb : s_on_connect)
	{
		cb();
	}
}

} // namespace app