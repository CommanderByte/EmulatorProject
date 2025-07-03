import logging
from typing import Callable, List, Dict, Any
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_FETCH, Uc

logger = logging.getLogger(__name__)

class HookManager:
    """
    Manages the registration, removal, and tracking of Unicorn hooks.

    This class is designed to work with the Unicorn Engine for emulation purposes.
    It facilitates the addition, removal, and management of hooks in the Unicorn
    emulation instance.

    :ivar uc: Unicorn engine instance used for hook registration.
    :type uc: Uc
    :ivar hooks: List to track registered hooks. Each hook is represented as a
        dictionary containing details such as the hook's handle, type, callback,
        address range, and optional user data.
    :type hooks: List[Dict[str, Any]]
    """

    def __init__(self, uc: Uc):
        """
        Represents an object initialized with a given unit of computation (`uc`)
        and maintains a collection of hooks that allow for tracking or modifying
        specific functionality during the execution cycle.

        Attributes:
            uc (Uc): The unit of computation that the object is associated with.
            hooks (List[Dict[str, Any]]): A collection of dictionary objects used
            to manage various hooks that can be integrated into the execution logic.

        :param uc: The unit of computation to initialize the instance with.
        :type uc: Uc
        """
        self.uc = uc
        self.hooks: List[Dict[str, Any]] = []

    def add_hook(self, hook_type: int, callback: Callable, begin: int = 1, end: int = 0, user_data: Any = None):
        """
        Add a hook to the Unicorn engine and manage it within the current instance. The method allows
        registration of a hook of a specific type with a given callback and address range. The hook
        is stored internally in a structured format for easier handling.

        :param hook_type: Type of the hook to be added.
        :type hook_type: int
        :param callback: Callable function that is executed when the hook is triggered.
        :type callback: Callable
        :param begin: Start address of the memory range for the hook. Defaults to 1.
        :type begin: int, optional
        :param end: End address of the memory range for the hook. Defaults to 0.
        :type end: int, optional
        :param user_data: User-defined data passed to the callback. Defaults to None.
        :type user_data: Any, optional
        :return: Handle to the created hook or None if the operation fails.
        :rtype: Optional[Any]
        """
        try:
            handle = self.uc.hook_add(hook_type, callback, user_data, begin, end)
            self.hooks.append({
                "handle": handle,
                "type": hook_type,
                "callback": callback,
                "range": (begin, end),
                "user_data": user_data
            })
            logger.debug(f"✅ Hook registered: type={hook_type}, callback {callback}, range=0x{begin:X}-0x{end:X}")
            return handle
        except Exception as e:
            logger.exception(f"❌ Failed to add hook: {e} (type {hook_type}, callback {callback}, range 0x{begin:X}-0x{end:X})")

            return None

    def remove_hook(self, handle):
        """
        Removes a hook from the Unicorn Engine's hook list and logs the process. Ensures
        that the specified hook handle is deleted, and updates the internal hook list
        accordingly.

        :param handle: The identifier for the hook to be removed.
        :type handle: any
        :return: None
        """
        try:
            self.uc.hook_del(handle)
            self.hooks = [h for h in self.hooks if h["handle"] != handle]
            logger.debug("🗑️ Hook removed successfully")
        except Exception as e:
            logger.error(f"❌ Failed to remove hook: {e}")

    def clear_all(self):
        """
        Clears all registered hooks in the system.

        This method iterates through a list of hooks and attempts to remove each hook
        using a provided `hook_del` function. If an exception occurs during the removal
        of a hook, it logs a warning with the specific error message. Once all
        available hooks are processed, the method clears the list of hooks and logs
        an informational message to indicate that the operation has completed.

        :param self:
            The object instance containing the `hooks` list and the `uc` (uncertain)
            object responsible for hook removal functionality.

        :return:
            None
        """
        for hook in self.hooks:
            try:
                self.uc.hook_del(hook["handle"])
            except Exception as e:
                logger.warning(f"⚠️ Error removing hook: {e}")
        self.hooks.clear()
        logger.info("🧹 All hooks cleared")

    def list_hooks(self):
        """
        Provides a method to retrieve and return the list of hooks associated with the object.

        :return: The list of hooks.
        :rtype: list
        """
        return self.hooks
