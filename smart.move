module AcademicCredentials::Verifier {
    use std::hash;
    use std::vector;
    use std::signer;

    // Define the Credential structure
    struct Credential has key, store {
        id: u64,
        name: vector<u8>,
        degree: vector<u8>,
        institution: vector<u8>,
        issued_at: u64,
        certificate_hash: vector<u8>,
    }

    // Function to issue a new credential
    public fun issue_credential(
        account: &signer,
        id: u64,
        name: vector<u8>,
        degree: vector<u8>,
        institution: vector<u8>,
        issued_at: u64,
    ) {
        // Create a vector to hold certificate data
        let mut certificate_data = vector::empty<u8>();

        // Append name, degree, and institution data
        certificate_data = vector::extend(certificate_data, &name);
        certificate_data = vector::extend(certificate_data, &degree);
        certificate_data = vector::extend(certificate_data, &institution);

        // Convert issued_at to bytes and append
        let issued_at_bytes = u64_to_bytes(issued_at);
        certificate_data = vector::extend(certificate_data, &issued_at_bytes);

        // Generate hash of the certificate data
        let certificate_hash = hash::sha3_256(certificate_data);

        // Create and store the credential
        let credential = Credential {
            id,
            name,
            degree,
            institution,
            issued_at,
            certificate_hash,
        };

        move_to(account, credential);
    }

    // Function to verify a credential based on ID and student-provided hash
    public fun verify_credential(
        account: &signer,
        id: u64,
        student_hash: vector<u8>,
    ): bool {
        if (exists<Credential>(signer::address_of(account))) {
            let credential = borrow_global<Credential>(signer::address_of(account));
            if (credential.id == id && credential.certificate_hash == student_hash) {
                return true;
            }
        }
        false
    }

    // Function to generate a secure QR code (returns certificate hash for now)
    public fun generate_qr_code(
        account: &signer,
        id: u64,
    ): vector<u8> {
        if (exists<Credential>(signer::address_of(account))) {
            let credential = borrow_global<Credential>(signer::address_of(account));
            if (credential.id == id) {
                // Placeholder: Replace with actual QR code generation logic
                return credential.certificate_hash;
            }
        }
        vector::empty<u8>() // Return an empty vector if no credential is found or id doesn't match
    }

    // Helper function to convert u64 to bytes
    fun u64_to_bytes(value: u64): vector<u8> {
        let mut bytes = vector::empty<u8>();
        for i in 0..8 {
            let byte = (value >> (i * 8)) as u8;
            bytes = vector::push_back(bytes, byte);
        }
        bytes
    }
}
