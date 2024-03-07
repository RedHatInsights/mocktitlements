let chai = require('chai');
let chaiHttp = require('chai-http');
let chaiJSON = require('chai-json');
var expect = chai.expect;
let should = chai.should();
var assert = chai.assert;


chai.use(chaiHttp);
chai.use(chaiJSON);

const url= 'http://localhost:8090';

let jdoeUser = {
  name: "jdoe",
  password: "BOO"
};

let xrhid= {"identity": {"type": "User", "account_number": "0000001", "org_id": "000001", "user": {"username": "jdoe"}, "internal": {"org_id": "000001"}}};
let xrhidb64= Buffer.from(JSON.stringify(xrhid)).toString('base64');

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
                JSON_response = JSON.parse(res.text);
                expect(Object.keys(JSON_response).length).eq(13);
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

describe('/POST /auth/realms/redhat-external/apis/service_accounts/v1',() => {
    it("should create a client and return the secret", (done) => {
        let serviceAccount = {"name":"abcde","description":"afasdf"}

        chai.request(url)
            .post('/auth/realms/redhat-external/apis/service_accounts/v1')
            .send(serviceAccount)
            .end((err,res) => {
                console.log(res.text)
                res.should.have.status(201);
                JSON_response = JSON.parse(res.text);
                expect(JSON_response['clientId']).eq("abcde");
                expect(JSON_response['id']).not().null();
            done();
        });
    });
});

describe('/GET /auth/realms/redhat-external/apis/service_accounts/v1?first=0&max=2',() => {
    it("should get a list of service accounts", (done) => {
        chai.request(url)
            .get('/auth/realms/redhat-external/apis/service_accounts/v1?first=0&max=2&org_id=12345')
            .end((err,res) => {
                console.log("rt")
                console.log(res.text)
                res.should.have.status(200);
                JSON_response = JSON.parse(res.text);
                console.log(JSON_response)
                expect(Object.values(JSON_response).length).eq(2);
            done();
        });
    });
});

// Test deleteServiceAccount functionality
describe('/DELETE /auth/admin/realms/redhat-external/clients/:ClientId',() => {
    it("should create a client to be deleted", (done) => {
        let serviceAccount = {"name":"test_service_account","description":"this should get deleted"}

        chai.request(url)
            .post('/auth/realms/redhat-external/apis/service_accounts/v1')
            .send(serviceAccount)
            .end((err,res) => {
                console.log("TESTING " + res.text)
                res.should.have.status(201);
                JSON_response = JSON.parse(res.text);
                expect(JSON_response['clientId']).eq("test_service_account");
                expect(JSON_response['id']).not().null();
            done();
        });
    });

    it("deletes newly created Keycloak service account", (done) => {
        chai.request(url)
            .delete('/auth/admin/realms/redhat-external/clients/da646fe7-8586-4202-8a2d-49c549f11d14')
            .end((err,res) => {
                res.should.have.status(204);
            done();
        });
    });
});
