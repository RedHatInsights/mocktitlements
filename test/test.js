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
