'use strict';

const kms = require('./kms')
const fs = require('fs/promises')
const ENCRYPT_PREFIX = 'encrypted:'

class ServerlessKMSPlugin {
  constructor(serverless, options) {
    this.serverless = serverless;
    this.options = options;

    this.commands = {
      encryptor: {
        usage: 'Encrypt value',
        lifecycleEvents: ['env'],
        options: {
          value: {
            usage: 'Value of the attribute',
            type: 'string'
          },
          variable: {
            usage: 'Name of the attribute',
            type: 'string'
          },
          decrypt: {
            usage: 'Denotes that variables should be decrypted',
            type: 'boolean'
          },
          common: {
            usage: 'Encrypt reusable variable',
            type: 'boolean'
          },
        },
      }
    }

    this.hooks = {
      'encryptor:env': this.encryptorCommand.bind(this),
    };
  }

  encryptorCommand() {
    let config = this.getConfig();
    if (this.options.decrypt) {
      return this.decryptCommand(config);
    }
    return this.encryptOption(config);
  }

  async encryptOption(config) {
    let filePath = './env.json';
    const json = await fs.readFile(filePath);
    const envObject = JSON.parse(json);
    const encrypted = await kms.encrypt(this.options.value, config);
    const value = `${ENCRYPT_PREFIX}${encrypted}`;
    this.serverless.cli.log(`Provided value: ${this.options.value}`);
    this.serverless.cli.log(`Encrypted value: ${encrypted}`);
    if (!this.options.variable) {
      return Promise.reject(new Error('Setting a value requires --variable'))
    }
    if (this.options.common) {
      envObject.common[this.options.variable] = value;
    } else {
      if (!envObject.stages[config.stage]) {
        envObject.stages[config.stage] = {};
      }
      envObject.stages[config.stage][this.options.variable] = value;
    }

    await fs.writeFile('./env.json', JSON.stringify(envObject));
    this.serverless.cli.log(`Successfuly set ${this.options.variable} for ${this.options.common ? 'common' : config.stage} environment 🎉`);
  }


  async decryptCommand(config) {
    if (!this.options.variable) {
      return Promise.reject(new Error('Setting a value requires --variable'))
    }
    let filePath = './env.json';
    const json = await fs.readFile(filePath);
    const envObject = JSON.parse(json);
    let value;
    if (this.options.common) {
      value = envObject.common?.[this.options.variable];
    } else {
      value = envObject.stages?.[config.stage]?.[this.options.variable];
    }
    if (!value) {
      return Promise.reject(new Error(`Could find ${this.options.variable} in ${this.options.common ? 'common' : config.stage} environment.`))
    }
    const regexp = new RegExp(`^${ENCRYPT_PREFIX}`);
    const toDecrypt = value.replace(regexp, '');
    const encrypted = await kms.decrypt(toDecrypt, config);
    this.serverless.cli.log(`Successfuly decrypted ${encrypted}`);
  }

  getConfig() {
    if (!this.config) {
      let servicePath = this.serverless.config.servicePath || './'
      let stage = this.serverless.processedInput.options.stage || this.serverless.service.provider.stage
      let keyId = this.serverless.service.custom.envEncryptionKeyId
      this.config = {
        region: this.serverless.processedInput.options.region || this.serverless.service.provider.region,
        profile: this.serverless.processedInput.options.profile || this.serverless.service.provider.profile,
        stage,
        servicePath,
        kmsKeyId: (typeof keyId === 'object') ? keyId[stage] : keyId
      }
    }
    return this.config
  }
}

module.exports = ServerlessKMSPlugin;
