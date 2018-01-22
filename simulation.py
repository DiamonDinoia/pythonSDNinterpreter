from router import *
from time import sleep
import random


def packet_generator(x=None):
    while True:
        if x:
            yield Packet(random.randrange(100000), random.randrange(x))
        else:
            yield Packet(random.randrange(100000), random.randrange(100000))


def dummy_policy(packet):
    return True


def main():
    router = Router()
    print('Router created', router)

    rules = [Rule(i, i) for i in range(9)]
    print('Created some rules', [str(rule) for rule in rules])

    table = Table(*rules)
    print('Table created', table)

    gen = packet_generator(9)
    packets = [next(gen) for _ in range(9)]
    print('Created some packets', [str(packet) for packet in packets])

    router.install_table(table)
    print('Table installed', router)

    def route():
        return [router.route(packet) for packet in packets]

    print('Failed routing some packets. Router not initialized. Interfaces: ', route())

    router.start_routing()
    print('Routing some packets. Interfaces: ', route())

    router.drop(rules[5])
    print('Dropped a rule', router)

    router.install_policy(dummy_policy)
    print('Installed a policy', router)

    router.delete(rules[7])
    print('deleted a rule', router)

    router.mobility(Rule(4, 20))
    print('mobility set', router)

    router.block()
    print('traffic blocked', route())

    print('starting endless simulation')
    for i in range(5):
        print('count-down:', str(5-i) + "!!!")
        sleep(1)
    router = Router()
    rules = [Rule(random.randrange(50), random.randrange(50)) for _ in range(50)]
    table = Table(*rules)
    router.install_table(table)
    router.install_policy(dummy_policy)
    router.start_routing()
    while True:
        print('interface:', router.route(next(packet_generator(50))))
        sleep(0.5)


if __name__ == "__main__":
    main()
