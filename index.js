var http = require('http');
var https = require('https');
var url = require('url');
var parseXML      = require('xml2js').parseString;
var XMLprocessors = require('xml2js/lib/processors');

module.exports =  {
    set: function(options) {
        if(typeof options == 'string') options = {base_url: options};
        if(!options.base_url) throw new Error('No CAS Base URL provided');
        if(!options.version||['1','2','3'].indexOf(options.version+'')==-1) options.version = '3';
        switch(options.version) {
            case '1':
                options.validateUrl = options.validateUrl||'/validate';
                options.validate = function(body, callback) {
                    var lines = body.split('\n');
                    if (lines[ 0 ] === 'yes' && lines.length >= 2) {
                        return callback(null, {user: lines[ 1 ]});
                    }
                    else if (lines[ 0 ] === 'no') {
                        return callback( new Error('CAS authentication failed.'));
                    }
                    else {
                        return callback( new Error('Response from CAS server was bad.'));
                    }
                }
                break;
            case '2':
                options.validateUrl = options.validateUrl||'/serviceValidate';
            default:
                options.validateUrl = options.validateUrl||'/p3/serviceValidate';
                options.validate = function(body, callback) {
                    parseXML(body, {
                        trim: true,
                        normalize: true,
                        explicitArray: false,
                        tagNameProcessors: [ XMLprocessors.normalize, XMLprocessors.stripPrefix ]
                    }, function(err, result) {
                        console.log(err)
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
                                return callback(null, {user: success.user, attributes: success.attributes});
                            }
                            else {
                                return callback(new Error( 'CAS authentication failed.'));
                            }
                        }
                        catch (err) {
                            console.log(err);
                            return callback(new Error('CAS authentication failed.'));
                        }
                    });
                };
        }
        this.options = options;
        this.parsed = url.parse(options.base_url+options.validateUrl);
        this.client = this.parsed.protocol == 'https'?https:http;
        return this;
    },
    /**
     * When encountered with an error, actions can be 
     *  'block': write response with errors
     *  'pass': pass error to next function
     *  'ignore': just call next without writing req.cas
     */
    validate: function(action) {
        if(!action||['block', 'pass', 'ignore'].indexOf(action)==-1) action='block';
        return function(req, res, next) {
            var doExit = function(status, message) {
                if(action == 'block') return res.writeHead(status, message);
                next(action=='pass'?nessage:null);
            }
            var ticket = req.query&&req.query.ticket;
            if(!ticket && req.headers.authorization) {
                var split = req.headers.authorization.split(' ');
                if(split[0]=='Bearer') ticket = split[1];
            }
            if(!ticket) return doExit(401, 'Unauthorized. No service ticket found or invalid.');
            parsed.query = {ticket: ticket};
            var self = this;
            var request = this.client.request(this.parsed, function(response) {
                var body='';
                response.on('data', function(chunk) {
                body += chunk; 
                });
                response.on('error', function(error) {
                    doExit(500, 'Error on validation response: '+error.message);
                });
                response.on('end', function() {
                    self.options.validate(body, function(error, data) {
                        if(error) return doExit(401, 'Unauthorized. No service ticket found or invalid.');
                        req.cas = data;
                        next();
                    });
                });
            });
            request.on('error', function(error){
                doExit(500, 'Error on validation request: '+error.message);
            });
            request.end();
        }
    }
};