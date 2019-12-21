class Packet(object):
    def get_checksum(self, fields):
        mod = 1 << 16

        result = 0
        for i in range(1, len(fields)):
            sum = fields[i-1] + fields[i]
            complement = sum if sum < mod else (sum + 1) % mod
            complement_sum = result + complement
            result = complement_sum if complement_sum < mod else (
                complement_sum + 1) % mod

        return ~result & 0xffff
