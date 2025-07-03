from dataclasses import dataclass

@dataclass(frozen=True)
class PortRange:
    """
    Represents a range of ports, inclusive of both start and end.

    The PortRange class defines a range of ports and provides utility methods
    to validate, compare, and represent the range. Instances of the class are
    immutable due to the frozen dataclass decorator, ensuring that port ranges
    remain consistent after creation.

    Attributes:
        start (int): The beginning of the port range.
        end (int): The end of the port range. Defaults to the value of `start`
                  if not explicitly provided.
    """
    start: int
    end: int = None  # Inclusive

    def __post_init__(self):
        """
        Perform post-initialization validation and adjustments for the PortRange object.

        This method ensures the integrity of the PortRange instance by setting the
        end attribute to be equal to the start attribute if the end is not explicitly
        provided. Additionally, it validates that the end attribute is not less than
        the start attribute, raising an error in such cases.

        Raises:
            ValueError: If the end attribute is less than the start attribute.
        """
        if self.end is None:
            object.__setattr__(self, "end", self.start)
        elif self.end < self.start:
            raise ValueError(f"Invalid PortRange: end {self.end} < start {self.start}")

    def contains(self, port: int) -> bool:
        """
        Checks if a given port number is within the defined range.

        This method evaluates if the provided port number lies inclusively between
        the start and end of the range. It is useful for validating if a specific
        port falls under the constraints of this range.

        Parameters:
        port (int): The port number to check.

        Returns:
        bool: True if the port is within the range, otherwise False.
        """
        return self.start <= port <= self.end

    def overlaps(self, other: "PortRange") -> bool:
        """
        Determines if two PortRange objects overlap.

        This method checks if the range of ports represented by the current
        PortRange instance overlaps with the range of ports represented by
        another PortRange instance. The method assumes that the start and end
        attributes of both instances are properly defined and represent valid
        ranges.

        Args:
            other (PortRange): Another PortRange object to compare with.

        Returns:
            bool: True if the two PortRanges overlap, False otherwise.
        """
        return not (self.end < other.start or self.start > other.end)

    def __str__(self):
        """
        Returns a string representation of the object.

        The string representation provides a hexadecimal representation of a range.
        If the start and end attributes are equal, it returns a single hexadecimal value.
        Otherwise, it returns a range in the format "start-end", where both start and
        end are represented in hexadecimal notation.

        Returns:
            str: Hexadecimal representation of the range or single value.
        """
        if self.start == self.end:
            return f"0x{self.start:X}"
        return f"0x{self.start:X}-0x{self.end:X}"
