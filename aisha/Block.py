from hashlib import sha256 
import json 
import time 

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        """
        :param index: Position of the block in the blockchain.
        :param transactions: List of certificate records.
        :param timestamp: Time of block creation.
        :param previous_hash: Hash of the previous block.
        """
        self.index = index
        self.transactions = transactions  # List of certificate transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = 0  # Used for mining (if PoW needed)

    def compute_hash(self):
        """
        Generates the SHA-256 hash of the block's contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()
