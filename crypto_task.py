from crypto_functions import strxor, hex_to_ascii, is_valid_text


def ciphertext_pair_from_midway_index(mh_index):
    length = len(cipherhexes) - 1

    ct_index1 = mh_index / length
    ct_index2 = mh_index % length + 1 if mh_index % length >= ct_index1 else mh_index % length

    return (ct_index1, ct_index2)

# We know the key length is 1024 bytes in length

# All the cipherhexes, PHEW!
cipherhexes= [
   0x315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e,
   0x234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f,
   0x32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb,
   0x32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa,
   0x3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070,
   0x32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4,
   0x32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce,
   0x315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3,
   0x271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027,
   0x466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83,
   0x32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904,
]

midwaytexts = []
ciphertexts = []

for ch in cipherhexes:
    ciphertexts.append(hex_to_ascii(ch))

for ct1 in ciphertexts:
    for ct2 in ciphertexts:
        if ct1 != ct2:
            midwaytexts.append(strxor(ct1, ct2))

# SANITY CHECKS TO ENSURE INTEGRITY
import crypto_tests
crypto_tests.run_crypto_test_suite()

for i, mt in enumerate(midwaytexts):
    index1, index2 = ciphertext_pair_from_midway_index(i)

    min_len = min(len(ciphertexts[index1]), len(ciphertexts[index2]))

    assert strxor(ciphertexts[index1], ciphertexts[index2]) == mt
    assert strxor(mt, ciphertexts[index1][:min_len]) == ciphertexts[index2][:min_len]
    assert strxor(mt, ciphertexts[index2][:min_len]) == ciphertexts[index1][:min_len]

# ======================== #
# ACTUAL CODE STARTS HERE  #
# ======================== #

def generate_potential_tuples(crib_text):
    """
    Generates list of tuples containing information about potentially decyrpted portions
    of the cipher text. 'Crib dragging' is used with the specified crib text in the
    parameters to generate the potential candidates.
    @param crib_text: crib text to use for the crib dragging technique.
    @return: list of potential tuples in the form of:
             (result_hex, result_text, text_pos, cipher_index_pair)

    where cipher_index pair is a tuple containing two indexes specifying the ciphertexts
    used to create the particular midwayhex used.
    """

    results = []
    
    for mt_index, mt in enumerate(midwaytexts):
        
        for mt_char_index, mt_char in enumerate(mt):
            if mt_char_index + len(crib_text) <= len(mt):
                mt_substring = mt[mt_char_index:mt_char_index + len(crib_text)]

                # Potentially valid text after applying the crib text
                attempt_text = strxor(mt_substring, crib_text)

                # Simple heuristic used to determine if the output is potentially valid
                if is_valid_text(attempt_text):

                    ch_index1, ch_index2 = ciphertext_pair_from_midway_index(mt_index)

                    sub_ciphertext_1 = ciphertexts[ch_index1][mt_char_index:mt_char_index + len(crib_text)]
                    sub_ciphertext_2 = ciphertexts[ch_index2][mt_char_index:mt_char_index + len(crib_text)]

                    # Generate the two potential keys
                    ptkey1 = strxor(sub_ciphertext_1, crib_text)
                    ptkey2 = strxor(sub_ciphertext_2, crib_text)

                    results.append((mt_char_index, ptkey1, crib_text))
                    results.append((mt_char_index, ptkey2, crib_text))

    return results


def test1(text):
    # Try each potential on the ciphertexts its associated with to produce potential sub-keys
    # Try each subkey on all other ciphertexts to see if output is reasonable. If it is, we have a piece of the key
    for pos, ptkey, text in generate_potential_tuples(text):
        start = pos
        end = pos + len(text)

        results = []
        valid_counter = 0
        
        for index, ct in enumerate(ciphertexts):
            out = strxor(ct[start:end], ptkey)
            results.append(out)
            if is_valid_text(out):
                valid_counter += 1

        # Simple filter to prevent clutter
        # Only print the results if more than half of them have valid text outputs
        if valid_counter > len(results) / 2:
            for i, r in enumerate(results):
                print 'ciphertext %s:' % i, r, '%s-%s' % (start, end), 'text=%s' % text

            print '=' * 50

# Take the system argument passed as the word to
# perform crib dragging with
# For convenience, it may be smart to pipe the results to a file or use the UNIX less pager
#
# * python crypto_task.py ' crib text ' > results.txt
# * python crypto_task.py ' crib text ' | less
import sys
test1(sys.argv[1])
