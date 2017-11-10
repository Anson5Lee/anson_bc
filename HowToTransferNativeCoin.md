<!-- ??????????????? -->
<!-- eth_addr -> otaAddr -> otaAddr -> refund -->

var qty = 5;

var sender = eth.accounts[1];
var recipient = eth.accounts[2];

personal.unlockAccount(sender, "wanglu", 9999);
personal.unlockAccount(recipient, "wanglu", 9999);

var senderOldBalance = web3.fromWei(eth.getBalance(sender))

var cABI = [{"constant":false,"type":"function","stateMutability":"nonpayable","inputs":[{"name":"OtaAddr","type":"string"},{"name":"Value","type":"uint256"}],"name":"buyCoinNote","outputs":[{"name":"OtaAddr","type":"string"},{"name":"Value","type":"uint256"}]},{"constant":false,"type":"function","inputs":[{"name":"RingSignedData","type":"string"},{"name":"Value","type":"uint256"}],"name":"refundCoin","outputs":[{"name":"RingSignedData","type":"string"},{"name":"Value","type":"uint256"}]},{"constant":false,"inputs":[],"name":"getCoins","outputs":[{"name":"Value","type":"uint256"}]}];

var cFactory = eth.contract(cABI);
var cAddr = "0x0000000000000000000000000000000000000005";
var cInstance = cFactory.at(cAddr);

var wanAddr = eth.getWanAddress(recipient);
var otaAddr = eth.generateOneTimeAddress(wanAddr);

var txMintData = cInstance.buyCoinNote.getData(otaAddr, web3.toWei(qty));
var txMintHash = eth.sendTransaction({from: sender, to: cAddr, value: web3.toWei(qty), data: txMintData, gas: 1000000});
<!-- var senderNewBalance = web3.fromWei(eth.getBalance(sender)) -->

<!-- var senderBalanceDelta = senderNewBalance - senderOldBalance -->
