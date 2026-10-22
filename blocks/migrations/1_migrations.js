const ex = artifacts.require('Store')
module.exports = (f) => {
    f.deploy(ex)
}