from bulbs.model import Node, Relationship
from bulbs.property import String, Integer, DateTime
from bulbs.utils import current_datetime

class Pe(Node):

    element_type = "pe"
    name = String(nullable=False)
    color = String(default="#FF0000")

class Transferred(Relationship):
    label = "transferred"
    element_type = label

class SentTo(Relationship):
    label = "sentTo"
    element_type = label

class SentBy(Relationship):
    label = "sentBy"
    element_type = label



