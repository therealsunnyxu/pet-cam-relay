from awscrt import mqtt
from awsiot import iotshadow, mqtt_connection_builder
from dotenv import dotenv_values
from models import NamedShadow
from uuid import uuid4
import copy
import json
import os
import secrets
import time

CWD = os.path.dirname(os.path.realpath(__file__))
CONFIG = dotenv_values(os.path.join(CWD, ".env"))
DIRECTORY_KEYS = ["CA", "CERT", "KEY"]
for key in DIRECTORY_KEYS:
    CONFIG[key] = os.path.abspath(os.path.join(CWD, CONFIG[key]))

BASE_PAYLOAD = {"state": {"reported": {"key": ""}}}


def make_new_key(byte_length: int):
    return secrets.token_urlsafe(byte_length)


def make_command_payload(status: str):
    return json.dumps({"command": status}).encode("utf-8")


def make_key_payload(payload: dict, key: str):
    if not payload.state.reported.key:
        raise ValueError(
            "Key must follow the structure: {}".format(
                {"state": {"reported": {"key": ""}}}
            )
        )

    new_payload = copy.deepcopy(payload)
    new_payload.state.reported.key = key

    return new_payload


def on_message_received(topic, payload, dup, qos, retain, **kwargs):
    print("Received message from topic '{}': {}".format(topic, payload))


if __name__ == "__main__":
    SHADOW_NAME = CONFIG["SHADOW_NAME"]
    CLIENT_ID = str(CONFIG["CLIENT_ID"])
    CAMERA_TOPIC = CONFIG["TOPIC"]

    # Make the connection to AWS IoT Core's MQTT broker
    try:
        mqtt_connection = mqtt_connection_builder.mtls_from_path(
            endpoint=CONFIG["ENDPOINT"],
            cert_filepath=CONFIG["CERT"],
            pri_key_filepath=CONFIG["KEY"],
            ca_filepath=CONFIG["CA"],
            client_id=CONFIG["CLIENT_ID"],
            clean_session=False,
        )

        connect_future = mqtt_connection.connect()
        shadow_client = iotshadow.IotShadowClient(mqtt_connection)
        stream_key_shadow = NamedShadow(shadow_client, SHADOW_NAME, CLIENT_ID)

        connect_future.result()
        print("Connected!")
    except Exception as e:
        exit(e)

    # Subscribe to own device shadow
    try:
        print("Subscribing to Update responses...")
        update_accepted_subscribed_future, _ = (
            shadow_client.subscribe_to_update_named_shadow_accepted(
                request=iotshadow.UpdateNamedShadowSubscriptionRequest(
                    shadow_name=stream_key_shadow.shadow, thing_name=CLIENT_ID
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
                callback=stream_key_shadow.on_update_shadow_accepted,
            )
        )

        update_rejected_subscribed_future, _ = (
            shadow_client.subscribe_to_update_named_shadow_rejected(
                request=iotshadow.UpdateNamedShadowSubscriptionRequest(
                    shadow_name=stream_key_shadow.shadow, thing_name=CLIENT_ID
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
                callback=stream_key_shadow.on_update_shadow_rejected,
            )
        )

        update_accepted_subscribed_future.result()
        update_rejected_subscribed_future.result()

        print("Subscribing to get responses...")
        get_accepted_subscribed_future, _ = (
            shadow_client.subscribe_to_get_named_shadow_accepted(
                request=iotshadow.GetNamedShadowSubscriptionRequest(
                    shadow_name=stream_key_shadow.shadow, thing_name=CLIENT_ID
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
                callback=stream_key_shadow.on_get_shadow_accepted,
            )
        )

        get_rejected_subscribed_future, _ = (
            shadow_client.subscribe_to_get_named_shadow_rejected(
                request=iotshadow.GetNamedShadowSubscriptionRequest(
                    shadow_name=stream_key_shadow.shadow, thing_name=CLIENT_ID
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
                callback=stream_key_shadow.on_get_shadow_rejected,
            )
        )

        get_accepted_subscribed_future.result()
        get_rejected_subscribed_future.result()

        print("Subscribing to Delta events...")
        delta_subscribed_future, _ = (
            shadow_client.subscribe_to_named_shadow_delta_updated_events(
                request=iotshadow.NamedShadowDeltaUpdatedSubscriptionRequest(
                    shadow_name=stream_key_shadow.shadow, thing_name=CLIENT_ID
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
                callback=stream_key_shadow.on_shadow_delta_updated,
            )
        )
        delta_subscribed_future.result()

        # Subscribe to camera topic to keep cameras alive
        print("Subscribing to topic '{}'...".format(CAMERA_TOPIC))
        subscribe_future, _ = mqtt_connection.subscribe(
            topic=CAMERA_TOPIC, qos=mqtt.QoS.AT_LEAST_ONCE, callback=on_message_received
        )

        result = subscribe_future.result()
        print("Subscribed with {}".format(str(result)))
    except Exception as e:
        exit(e)

    # Save the stream key to the device shadow and a file for other internal services to use
    try:
        with stream_key_shadow.locked_data.lock:
            token = str(uuid4())

            publish_get_future = shadow_client.publish_get_named_shadow(
                request=iotshadow.GetNamedShadowRequest(
                    shadow_name=stream_key_shadow.shadow,
                    thing_name=CLIENT_ID,
                    client_token=token,
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )

            stream_key_shadow.locked_data.request_tokens.add(token)
        publish_get_future.result()

        stream_key = CONFIG["STREAM_KEY"]#make_new_key(int(CONFIG["STREAM_KEY_LENGTH"]))
        stream_key_shadow.change_shadow_value(stream_key)
    except Exception as e:
        exit(e)
    
    # Continously send keep-alive message to cameras
    try:
        while True:
            message = make_command_payload("keepalive")
            print("Publishing message to topic '{}': {}".format(CAMERA_TOPIC, message))
            alive_future, _ = mqtt_connection.publish(
                topic=CAMERA_TOPIC, payload=message, qos=mqtt.QoS.AT_LEAST_ONCE
            )
            result = alive_future.result()
            time.sleep(int(CONFIG["KEEP_ALIVE_SECONDS"]))
    except Exception as e:
        exit(e)

