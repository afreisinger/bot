class CustomError(Exception):
    """Clase base para errores personalizados."""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class FunctionNotFoundError(CustomError):
    """La función no existe."""

    def __init__(self, function):
        super().__init__(f"La función '{function}' no existe en el sistema.")
        self.function = function




class InvalidRoleError(CustomError):
    """El rol no existe."""

    def __init__(self, rol):
        super().__init__(f"El rol '{rol}' no existe.")
        self.rol = rol


class UserNotFoundError(CustomError):
    """El usuario no es miembro ni administrador."""

    def __init__(self, user_id):
        super().__init__(f"El usuario '{user_id}' no es miembro ni administrador.")
        self.user_id = user_id
