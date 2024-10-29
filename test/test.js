let chai = require('chai');
let chaiHttp = require('chai-http');
let chaiJSON = require('chai-json');
var expect = chai.expect;
const { Issuer, custom } = require('openid-client');

let client;
let tokenSet;
let should = chai.should();
var assert = chai.assert;


chai.use(chaiHttp);
chai.use(chaiJSON);

const url= 'http://localhost:8090';
const kcurl= 'http://localhost:8080';

let jdoeUser = {
    name: "jdoe",
    password: "BOO"
};

let xrhid= {"identity": {"type": "User", "account_number": "0000001", "org_id": "000001", "user": {"username": "jdoe"}, "internal": {"org_id": "000001"}}};
let xrhidb64= Buffer.from(JSON.stringify(xrhid)).toString('base64');

before(async function() {
    try{
    const issuer = await Issuer.discover(kcurl+'/auth/realms/master');
    console.log('OpenID Provider discovered:', issuer.metadata.issuer);

    // Create a client instance
    client = new issuer.Client({
        client_id: 'admin-cli',
        client_secret: '',
    });

    // Perform ROPC grant to obtain tokens
    tokenSet = await client.grant({
        grant_type: 'password',
        username: 'admin',
        password: 'change_me',
        scope: 'openid', // Add scopes if necessary
    });

    } catch (error) {
        console.error('Error during setup:', error);
        const decoder = new TextDecoder();
        const str = decoder.decode(error.response.body);
        console.error('Error during setup:', str);
        throw error; // Rethrow the error to fail the test suite
    }
});

/*
 * Test / route
 */
describe('/GET /',() => {
    it('should return 200', (done) => {
        chai.request(url)
            .get('/')
            .end((err,res) => {
                res.should.have.status(200);
            done();
        });
    });
});

describe('/POST /api/entitlements/v1/services',() => {
    it("should return users entitlements if user found", (done) => {
        console.log(xrhidb64)
        chai.request(url)
            .post('/api/entitlements/v1/services')
            .set("x-rh-identity", xrhidb64)
            .end((err,res) => {
                res.should.have.status(200);
                const responseJSON = JSON.parse(res.text);
                
                responseJSON.ansible.should.have.property('is_entitled').that.is.true;
                responseJSON.ansible.should.have.property('is_trial').that.is.false;

                responseJSON.notifications.should.have.property('is_entitled').that.is.true;
                responseJSON.notifications.should.have.property('is_trial').that.is.false;
            done();
        });
    });
});

describe('/POST /api/entitlements/v1/services',() => {
    let badxrhid= {"identity": {"type": "User", "account_number": "0000001", "org_id": "000001", "user": {"username": "mark"}, "internal": {"org_id": "000001"}}};
    let badxrhidb64= Buffer.from(JSON.stringify(badxrhid)).toString('base64');
    
    it("should return 403 if user not found", (done) => {
        console.log(xrhidb64)
        chai.request(url)
            .post('/api/entitlements/v1/services')
            .set("x-rh-identity", badxrhidb64)
            .end((_err,res) => {
                res.should.have.status(403);
                res.text.should.contain("couldn't find user")
            done();
        });
    });
});

describe('/POST /api/entitlements/v1/services',() => {
    let badxrhid= {"identity": {"type": "User", "account_number": "0000001", "org_id": "000001", "internal": {"org_id": "000001"}}};
    let badxrhidb64= Buffer.from(JSON.stringify(badxrhid)).toString('base64');
    
    it("should return 403 if user not in xrhid", (done) => {
        console.log(xrhidb64)
        chai.request(url)
            .post('/api/entitlements/v1/services')
            .set("x-rh-identity", badxrhidb64)
            .end((_err,res) => {
                res.should.have.status(403);
                res.text.should.contain("x-rh-identity does not contain username ok")
            done();
        });
    });
});

describe('/POST /api/entitlements/v1/services',() => {
    it("should return 403 if no xrhid", (done) => {
        chai.request(url)
            .post('/api/entitlements/v1/services')
            .end((_err,res) => {
                res.should.have.status(403);
                res.text.should.contain("no x-rh-identity header")
            done();
        });
    });
});

describe('/POST /api/entitlements/v1/compliance',() => {
    it("should find users if sent usernames", (done) => {
        console.log(xrhidb64)
        chai.request(url)
            .post('/api/entitlements/v1/compliance')
            .set("x-rh-identity", xrhidb64)
            .send({"users": ["jdoe"]})
            .end((err,res) => {
                console.log(res.text)
                res.should.have.status(200);
                res.text.should.contain("OK")
            done();
        });
    });
});


// Test getServiceAccount
describe('/GET /auth/realms/redhat-external/apis/service_accounts/v1?first=0&max=50',() => {
    it("should get an empty list of service accounts", (done) => {
        chai.request(url)
            .get('/auth/realms/redhat-external/apis/service_accounts/v1?first=0&max=50')
            .set("x-rh-identity", xrhidb64)
            .end((err,res) => {
                JSON_response = JSON.parse(res.text);
                console.log(JSON_response)

                res.should.have.status(200);

                expect(Object.values(JSON_response).length).eq(0);

            done();
        });
    });
});

// Test createServiceAccount
let id_1 = "";
let id_2 = "";
describe('/POST /auth/realms/redhat-external/apis/service_accounts/v1',() => {
    it("should create a client to be deleted", (done) => {
        let serviceAccount1 = {"name":"integration_test_sa_1","description":"first integration test service account created"}

        chai.request(url)
        .post('/auth/realms/redhat-external/apis/service_accounts/v1')
        .set("x-rh-identity", xrhidb64)
        .send(serviceAccount1)
        .end((err, res) => {

            JSON_response = JSON.parse(res.text);
    
            res.should.have.status(201);
            id_1 = JSON_response['clientId'];
            expect(JSON_response['id']).not.null;
            expect(JSON_response['clientId']).not.null;
            expect(JSON_response['secret']).not.null;
            expect(JSON_response['name']).eq("service-account-" + id_1);
            expect(JSON_response['description']).eq("first integration test service account created");
            expect(JSON_response['createdBy']).eq("jdoe");
            expect(JSON_response['createdAt']).not.null;

            expect(JSON_response['id']).eq(JSON_response['clientId'])
    
            // Chain the client.requestResource() call inside the Chai request's end() callback
            client.requestResource(kcurl + '/auth/admin/realms/redhat-external/users?enabled=true', tokenSet)
                .then((resourceResponse) => {
                    // Assert the response or perform other checks
                    expect(resourceResponse.statusCode).eq(200);
                    JSON_response = JSON.parse(resourceResponse.body);
                    let found = 0;
                    JSON_response.forEach(element => {
                        if (element['username'] == "service-account-" + id_1) {
                            found = 1;
                            expect(element['attributes']['newEntitlements']).to.have.lengthOf(13);
                        }
                    });
                    expect(found).eq(1);
                    done();
                }).catch(error => {
                    done(error);
                })
                
        });

    });
        it("should create a client to be deleted", (done) => {
        let serviceAccount2 = {"name":"integration_test_sa_2","description":"second integration test service account created"}
        
        chai.request(url)
            .post('/auth/realms/redhat-external/apis/service_accounts/v1')
            .set("x-rh-identity", xrhidb64)
            .send(serviceAccount2)
            .end((err,res) => {
                console.log(res.text)
                JSON_response = JSON.parse(res.text);
                console.log(JSON_response)

                res.should.have.status(201);

                id_2 = JSON_response['clientId'];
                expect(JSON_response['id']).not.null;
                expect(JSON_response['clientId']).not.null;
                expect(JSON_response['secret']).not.null;
                expect(JSON_response['name']).eq("service-account-"+ id_2);
                expect(JSON_response['description']).eq("second integration test service account created");
                expect(JSON_response['createdBy']).eq("jdoe");
                expect(JSON_response['createdAt']).not.null;

                
            done();
        });
    });
});

// Test getServiceAccount
describe('/GET /auth/realms/redhat-external/apis/service_accounts/v1?first=0&max=50',() => {
    it("should get a list of service accounts", (done) => {
        chai.request(url)
            .get('/auth/realms/redhat-external/apis/service_accounts/v1?first=0&max=50')
            .set("x-rh-identity", xrhidb64)
            .end((err,res) => {
                console.log(res.text)
                JSON_response = JSON.parse(res.text);
                

                res.should.have.status(200);

                expect(Object.values(JSON_response).length).eq(2);

                expect(JSON_response[0]['createdBy']).eq("jdoe");
                expect(JSON_response[1]['createdBy']).eq("jdoe");
            done();
        });
    });
});

// Test deleteServiceAccount
describe('/DELETE /auth/realms/redhat-external/apis/service_accounts/v1/:ClientId',() => {
    it("deletes newly created Keycloak service account", (done) => {
        console.log(id_1)
        chai.request(url)
            .delete('/auth/realms/redhat-external/apis/service_accounts/v1/' + id_1)
            .set("x-rh-identity", xrhidb64)
            .end((err,res) => {
                res.should.have.status(204);
            done();
        });
    });

    it("deletes newly created Keycloak service account", (done) => {
        console.log(id_2)
        chai.request(url)
            .delete('/auth/realms/redhat-external/apis/service_accounts/v1/' + id_2)
            .set("x-rh-identity", xrhidb64)
            .end((err,res) => {
                res.should.have.status(204);
            done();
        });
    });

    // TODO: Add test to attempt to get a deleted SA
});

describe("/GET /auth/realms/redhat-external/apis/service_accounts/v1/", () => {
    it("should get a 404 when trying to access an invalid account", (done) => {
        chai.request(url)
        .get('/auth/realms/redhat-external/apis/service_accounts/v1/1337')
        .set("x-rh-identity", xrhidb64)
        .end((err,res) => {
            res.should.have.status(404);
            done();
        });
    });    
});


describe('/POST /auth/realms/redhat-external/apis/service_accounts/v1 /GET and /DELETE',() => {
    let id_3 = "";
    it("should create a client to be gotten before being deleted", (done) => {
        let serviceAccount1 = {"name":"integration_test_sa_1","description":"first integration test service account created"}

        chai.request(url)
        .post('/auth/realms/redhat-external/apis/service_accounts/v1')
        .set("x-rh-identity", xrhidb64)
        .send(serviceAccount1)
        .end((err, res) => {

            JSON_response = JSON.parse(res.text);
    
            res.should.have.status(201);
            id_3 = JSON_response['clientId'];
            done();
        });
    });
    it("should get a single service accounts", (done) => {
        chai.request(url)
            .get('/auth/realms/redhat-external/apis/service_accounts/v1/' + id_3)
            .set("x-rh-identity", xrhidb64)
            .end((err,res) => {
                JSON_response = JSON.parse(res.text);
                console.log(JSON_response)

                res.should.have.status(200);

                expect(JSON_response['createdBy']).eq("jdoe");
                expect(JSON_response['id']).eq(id_3);
                expect(JSON_response['clientId']).eq(id_3);
            done();
        });
    });
    it("deletes service account", (done) => {
        console.log(id_3)
        chai.request(url)
            .delete('/auth/realms/redhat-external/apis/service_accounts/v1/' + id_3)
            .set("x-rh-identity", xrhidb64)
            .end((err,res) => {
                res.should.have.status(204);
            done();
        });
    });
});
