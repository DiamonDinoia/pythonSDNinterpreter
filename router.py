from enum import Enum
from inspect import signature


class Action(Enum):
    """Action contained in the rule"""
    route = 0
    drop = 1


class Status(Enum):
    """Status of the router"""
    routing = 0
    blocking = 1
    uninitialized = 2


class Packet:
    """Generic packet forwarded by routers into the network"""
    def __init__(self, source=None, destination=None, data=None):
        super().__init__()
        self.source = source
        self.destination = destination
        self.data = data

    def __str__(self):
        return ' '.join(["source:", str(self.source), "destination:", str(self.destination)])


class Rule:
    """This class represents a rule of the table"""
    def __init__(self, address=None, interface=None, action=Action.route):
        super().__init__()
        self.address = address
        self.interface = interface
        self.action = action

    def match(self, packet):
        return self.address == packet.destination

    def __str__(self):
        return ' '.join(['address: ', str(self.address), 'action: ',
                         str(self.action), 'interface: ', str(self.interface)])


class Table:
    """This class represents a routing table used by router in order to perform the correct forwarding"""

    def __init__(self, *rule):
        """Creation of a routing table"""
        super().__init__()
        self.rules = rule

    def __str__(self):
        return ', '.join(['[' + str(rule) + ']' for rule in self.rules])

    def match(self, packet):
        """perform a match between packets and table"""
        for rule in self.rules:
            if rule.match(packet) and rule.action == Action.route:
                return rule.interface
        return None

    def modify(self, rule):
        """modify a rule, in order to handle mobility"""
        self.rules = [x if x.address != rule.address else Rule(x.address, rule.interface, x.action) for x in self.rules]

    def delete(self, rule):
        """delete a rule"""
        self.rules = [x for x in self.rules if x.address != rule.address]

    def drop(self, rule):
        """sets a rule to drop"""
        self.rules = [x if x.address != rule.address else Rule(x.address, x.interface, Action.drop) for x in self.rules]


class Router:
    """This class model a generic router of the network"""

    def __init__(self, table=None, policy=None, status=Status.uninitialized):
        """Initializer leaving default parameters leaves a not working router"""
        super().__init__()
        self.table = None
        self.policy = None
        # I use this methods in order to make expandability easier (is not necessary)
        self.install_table(table)
        self.install_policy(policy)
        self.status = status

    def __str__(self):
        if self.policy:
            return ' '.join(['status:', str(self.status), 'table: {', str(self.table) + '}',
                             'policy:', str(signature(self.policy))])
        else:
            return ' '.join(['status:', str(self.status), 'table: {', str(self.table) + '}',
                             'policy:', str(self.policy)])

    def route(self, packet):
        """Implements the behaviour of the router, returns the correct forwarding interface"""
        if not self.status == Status.routing:
            return None
        if not self.table:
            return None
        if self.policy and not self.policy(packet):
            return None
        return self.table.match(packet)

    def install_table(self, table):
        """Install a table into the router"""
        self.table = table

    def install_policy(self, policy):
        """Install a policy into the router"""
        self.policy = policy

    def start_routing(self):
        """Enable the router"""
        self.status = Status.routing

    def block(self):
        """Blocks the traffic"""
        self.status = Status.blocking

    def mobility(self, rule=None, address=None, interface=None):
        """Handles the mobility"""
        if rule:
            self.table.modify(rule)
        elif address and interface:
            self.table.modify(Rule(address, interface))
        else:
            raise ValueError('Rule or (address,interface) must not be None')

    def drop(self, rule=None, address=None):
        """Sets a rule to drop"""
        if rule:
            self.table.drop(rule)
        elif address:
            self.table.drop(Rule(address))
        else:
            raise ValueError('Rule or address must not be None')

    def delete(self, rule=None, address=None):
        """Delete a rule from the table"""
        if rule:
            self.table.modify(rule)
        elif address:
            self.table.delete(Rule(address))
        else:
            raise ValueError('Rule or address must not be None')
