from awscrt import mqtt
from awsiot import iotshadow
import threading
from uuid import uuid4


class LockedData:
    """
    AWS SDK sample implementation of a value with a mutex
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.shadow_value = None
        self.disconnect_called = False
        self.request_tokens = set()


class NamedShadow:
    """
    Closure class for named shadow event functions, derived from AWS SDK samples
    """
    def __init__(
        self,
        client: iotshadow.IotShadowClient,
        shadow: str,
        thing_name: str,
        default_value: str = "",
    ):
        self.shadow = shadow
        self.thing_name = thing_name
        self.locked_data = LockedData()
        self.client = client
        self.default_value = default_value

    def on_update_shadow_accepted(self, response: iotshadow.UpdateShadowResponse):
        """Callback for updating the value of the device shadow
        Args:
            response (iotshadow.UpdateShadowResponse): The response from AWS
        """
        try:
            with self.locked_data.lock:
                try:
                    self.locked_data.request_tokens.remove(response.client_token)
                except KeyError:
                    print(
                        "Ignoring update_shadow_accepted message due to unexpected token."
                    )
                    return

            try:
                if response.state.reported is not None:
                    if self.shadow in response.state.reported:
                        print(
                            "Finished updating reported shadow value."
                        )
                    else:
                        print(
                            "Could not find shadow property with name: '{}'.".format(
                                self.shadow
                            )
                        )
                else:
                    print("Shadow states cleared.")
            except BaseException:
                exit("Updated shadow is missing the target property")

        except Exception as e:
            print(e)

    def on_update_shadow_rejected(self, error: iotshadow.UpdateShadowResponse):
        """Callback for when updating the value of the device shadow doesn't work
        Args:
            error (iotshadow.UpdateShadowResponse): The response from AWS
        """
        try:
            with self.locked_data.lock:
                try:
                    self.locked_data.request_tokens.remove(error.client_token)
                except KeyError:
                    print(
                        "Ignoring update_shadow_rejected message due to unexpected token."
                    )
                    return

            exit(
                "Update request was rejected. code:{} message:'{}'".format(
                    error.code, error.message
                )
            )

        except Exception as e:
            print(e)

    def set_local_value_due_to_initial_query(self, reported_value: str):
        """Updates the local value

        Args:
            value (str): The new value of the device shadow
        """
        with self.locked_data.lock:
            self.locked_data.shadow_value = reported_value

    def change_shadow_value(self, value: str):
        """Changes the shadow value both locally and on AWS

        Args:
            value (str): The new value of the device shadow
        """
        with self.locked_data.lock:
            if self.locked_data.shadow_value == value:
                print("Local value is already set.")
                return

            print("Changed local shadow value.")
            self.locked_data.shadow_value = value

            print("Updating reported shadow value.")
            token = str(uuid4())
            if value == "clear_shadow":
                tmp_state = iotshadow.ShadowState(
                    reported=None,
                    desired=None,
                    reported_is_nullable=True,
                    desired_is_nullable=True,
                )
                request = iotshadow.UpdateNamedShadowRequest(
                    shadow_name=self.shadow,
                    thing_name=self.thing_name,
                    state=tmp_state,
                    client_token=token,
                )
            else:
                if value == "none":
                    value = None

                request = iotshadow.UpdateNamedShadowRequest(
                    shadow_name=self.shadow,
                    thing_name=self.thing_name,
                    state=iotshadow.ShadowState(
                        reported={self.shadow: value},
                        desired={self.shadow: value},
                    ),
                    client_token=token,
                )

            future = self.client.publish_update_named_shadow(
                request, mqtt.QoS.AT_LEAST_ONCE
            )

            self.locked_data.request_tokens.add(token)

            future.add_done_callback(self.on_publish_update_shadow)

    def on_get_shadow_accepted(self, response: iotshadow.GetShadowResponse):
        """Callback for getting the value of the device shadow
        Args:
            response (iotshadow.GetShadowResponse): The response from AWS
        """
        try:
            with self.locked_data.lock:
                try:
                    self.locked_data.request_tokens.remove(response.client_token)
                except KeyError:
                    print(
                        "Ignoring get_shadow_accepted message due to unexpected token."
                    )
                    return

                print("Finished getting initial shadow state.")
                if self.locked_data.shadow_value is not None:
                    print(
                        "  Ignoring initial query because a delta event has already been received."
                    )
                    return

            if response.state:
                if response.state.delta:
                    value = response.state.delta.get(self.shadow)
                    if value:
                        print("  Shadow contains delta value.")
                        self.change_shadow_value(value)
                        return

                if response.state.reported:
                    value = response.state.reported.get(self.shadow)
                    if value:
                        print("  Shadow contains reported value.")
                        self.set_local_value_due_to_initial_query(
                            response.state.reported[self.shadow]
                        )
                        return

            print(
                "  Shadow document lacks '{}' property. Setting defaults...".format(
                    self.shadow
                )
            )
            self.change_shadow_value(self.default_value)
            return

        except Exception as e:
            print(e)

    def on_get_shadow_rejected(self, error: iotshadow.GetShadowResponse):
        """Callback for when getting the value of the device shadow doesn't work
        Args:
            error (iotshadow.GetShadowResponse): The response from AWS
        """
        try:
            with self.locked_data.lock:
                try:
                    self.locked_data.request_tokens.remove(error.client_token)
                except KeyError:
                    print(
                        "Ignoring get_shadow_rejected message due to unexpected token."
                    )
                    return

            if error.code == 404:
                print("Thing has no shadow document. Creating with defaults...")
                self.change_shadow_value(self.default_value)
            else:
                exit(
                    "Get request was rejected. code:{} message:'{}'".format(
                        error.code, error.message
                    )
                )

        except Exception as e:
            print(e)

    def on_shadow_delta_updated(self, delta):
        """Callback for getting the delta (change) of the value of the device shadow
        Args:
            delta: The response from AWS
        """
        try:
            print("Received shadow delta event.")
            if delta.state and (self.shadow in delta.state):
                value = delta.state[self.shadow]
                if value is None:
                    print(
                        "  Delta reports that '{}' was deleted. Resetting defaults...".format(
                            self.shadow
                        )
                    )
                    self.change_shadow_value(self.default_value)
                    return
                else:
                    print(
                        "  Delta reports that desired value is different. Changing local value..."
                    )
                    if delta.client_token is not None:
                        print("  ClientToken is: " + delta.client_token)
                    self.change_shadow_value(value)
            else:
                print("  Delta did not report a change in '{}'".format(self.shadow))

        except Exception as e:
            print(e)

    def on_publish_update_shadow(self, future):
        try:
            future.result()
            print("Update request published.")
        except Exception as e:
            print("Failed to publish update request.")
            print(e)
