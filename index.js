var http = require('http');
var https = require('https');
var URL = require('url');
var qs = require('querystring');
var parseXML = require('xml2js').parseString;
var XMLprocessors = require('xml2js/lib/processors');
var debug = require('debug')('cas-secure');

module.exports = {
  set: function(options) {
    if (typeof options === 'string') {
      options = {
        base_url: options
      };
    }

    if (!options.base_url) {
      throw new Error('No CAS Base URL provided');
    }

    if (!options.version || ['1', '2', '3'].indexOf(options.version + '') === -1) {
      options.version = '3';
    }

    if (!options.action || ['block', 'pass', 'ignore'].indexOf(options.action) === -1) {
      options.action = 'block';
    }

    switch (options.version) {
      case '1':
        options.validateUrl = options.validateUrl || '/validate';
        options.validate = function(body, callback) {
          var lines = body.split('\n');

          if (lines[0] === 'yes' && lines.length >= 2) {
            return callback(null, {
              user: lines[1]
            });
          } else if (lines[0] === 'no') {
            return callback(new Error('CAS authentication failed.'));
          } else {
            return callback(new Error('Response from CAS server was bad.'));
          }
        };
        break;
      case '2':
        options.validateUrl = options.validateUrl || '/proxyValidate';
        break;
      default:
        options.validateUrl = options.validateUrl || '/p3/proxyValidate';
        options.validate = function(body, callback) {
          parseXML(body, {
            trim: true,
            normalize: true,
            explicitArray: false,
            tagNameProcessors: [XMLprocessors.normalize, XMLprocessors.stripPrefix]
          }, function(err, result) {
            if (err) {
              return callback(new Error('Response from CAS server was bad.'));
            }
            try {
              var failure = result.serviceresponse.authenticationfailure;

              if (failure) {
                return callback(new Error('CAS authentication failed (' + failure.$.code + ').'));
              }

              var success = result.serviceresponse.authenticationsuccess;

              if (success) {
                return callback(null, {
                  user: success.user,
                  attributes: success.attributes
                });
              } else {
                return callback(new Error('CAS authentication failed.'));
              }
            } catch (error) {
              debug('Exception stacktrace: ');
              debug(error);
              return callback(new Error('CAS authentication failed.'));
            }
          });
        };
    }

    this.options = options;
    this.parsed = new URL(options.base_url + options.validateUrl);
    this.client = this.parsed.protocol === 'https' ? https : http;
    return this;
  },
  validate: function(action) {
    var self = this;

    if (!action || ['block', 'pass', 'ignore'].indexOf(action) === -1) {
      action = this.options.action;
    }

    return function(req, res, next) {
      var doExit = function(status, message) {
        debug('Status: ' + status + ' ' + message);

        if (action === 'block') {
          res.writeHead(status);
          return res.end(message);
        }

        var error = new Error(message);
        error.statusCode = status;

        next(action === 'pass' ? error : null);
      };

      var ticket = req.query && req.query.ticket;

      if (!ticket && req.headers.authorization) {
        var split = req.headers.authorization.split(' ');

        if (split[0] === 'Bearer') {
          ticket = split[1];
        }
      }

      if (!ticket) {
        debug('no ticket found');
        return doExit(401, 'Unauthorized. No service ticket found or invalid.');
      }

      var service = req.query && req.query.service;

      self.parsed.search = qs.stringify({
        ticket: ticket,
        service: self.options.service || req.headers.host
      });

      debug('Sending request to: ' + self.parsed.href);

      var request = self.client.request(self.parsed.href, function(response) {
        var body = '';

        response.on('data', function(chunk) {
          body += chunk;
        });

        response.on('error', function(error) {
          doExit(500, 'Error on validation response: ' + error.message);
        });

        response.on('end', function() {
          debug('Response body: ' + body);

          self.options.validate(body, function(error, data) {
            if (error) {
              debug('Error on validation: ' + error.message);
              return doExit(401, 'Unauthorized. No service ticket found or invalid.');
            }

            req.cas = data;
            process.nextTick(next);
          });
        });
      });

      request.on('error', function(error) {
        doExit(500, 'Error on validation request: ' + error.message);
      });

      request.end();
    };
  }
};
