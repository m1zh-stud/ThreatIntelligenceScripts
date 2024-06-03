
import os
def get_or_set_env_variable(var_name):
    var_value = os.getenv(var_name)
    if var_value is None:
        var_value = input(f"Please enter the value for {var_name}: ")
        os.environ[var_name] = var_value
    return var_value
get_or_set_env_variable("VirusTotalAPI")


