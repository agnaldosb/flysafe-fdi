#include "flysafe-tag.h"
#include "ns3/vector.h"
#include <iomanip> 
#include <sstream> 
#include <cstring>

/* ========================================================================
 * MyTag class
 *
 * Inherited from Tag class
 *
 * Create and add tags to packets
 *
 * ========================================================================
 */

static const uint8_t MY_TAG_MAGIC = 0xAB; // Vinicius - MiM - Nov 19, 2025 - Identify a encrypted data

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("MyTag"); // Vinicius - MiM - Nov 19, 2025

/**
 * \brief Get the type ID.
 * \return the object TypeId
 */
TypeId MyTag::GetTypeId(void) {
  static TypeId tid =
      TypeId("ns3::MyTag")
          .SetParent<Tag>()
          .AddConstructor<MyTag>()
          .AddAttribute("SimpleValue", "A simple value", EmptyAttributeValue(),
                        MakeUintegerAccessor(&MyTag::GetSimpleValue),
                        MakeUintegerChecker<uint8_t>());
  return tid;
}

TypeId MyTag::GetInstanceTypeId(void) const { return GetTypeId(); }

/**
 * @brief Get size of serialized data
 * @date Nov 10, 2022
 * @return uint32_t 
 */
uint32_t MyTag::GetSerializedSize (void) const
{
	//return sizeof(Vector) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(vector<NeighInfos>);
	//return sizeof(Vector) + sizeof(uint8_t) + sizeof(uint32_t) + (sizeof(NeighInfos) * m_nNeighborsValue) + sizeof(double);

	
	// Vinicius - MiM - Nov 13, 2025 - Fixed size: U8(magic number) + U8(tag) + Double(time) + U32(n_neigh) + Vector(pos)
    uint32_t fixedSize = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(double) + sizeof(uint32_t) + (3 * sizeof(double));
    
    // Vinicius - MiM - Nov 13, 2025 - Variable size 1: String size (U32) + string data
    uint32_t keySize = sizeof(uint32_t) + m_publicKey.size();
    
    // Vinicius - MiM - Nov 13, 2025 - Variable size 2: Vector Data
    uint32_t vectorSize = sizeof(NeighInfos) * m_neighInfosVector.size();;

    return fixedSize + keySize + vectorSize;
}

/**
 * @author Vinicius - MiM
 * @date Nov 17, 2025 
 * @brief Get the size of the serialized data including encryption overhead
 * @param key The encryption key
 * @param nonce The encryption nonce
 */
uint32_t MyTag::GetSerializedSize(const std::string& key, const std::string& nonce) const
{
    uint32_t clearSize = GetSerializedSize();
    return clearSize + CRYPTO_ABYTES;
}

/**
 * @brief Serialize tag value and nodes position. The order of how you do Serialize() should match the order of Deserialize()
 * @date Nov 10, 2022 (Created)
 * @date Jan 19, 2023 (Everaldo - Include neigbhors list copy)
 * 
 * @param i Tag data buffer
 */
void MyTag::Serialize (TagBuffer i) const
{	

    i.WriteU8(MY_TAG_MAGIC); // Vinicius - MiM - Nov 19, 2025 - Identify a encrypted data

	i.WriteU8(m_simpleValue); // Store tag value first
	i.WriteDouble(m_messageTime); // Store message sent time 

	uint32_t actualNeighbors = m_neighInfosVector.size();
    i.WriteU32(actualNeighbors); // Store number of neighbors value

	i.WriteDouble (m_currentPosition.x); // Store the position
	i.WriteDouble (m_currentPosition.y);
	i.WriteDouble (m_currentPosition.z);

	// Vinicius - MiM - Nov 13, 2025 - Store public key
	uint32_t keySize = m_publicKey.size();
    i.WriteU32(keySize);
    if (keySize > 0) {
        i.Write((const uint8_t*)m_publicKey.c_str(), keySize);
    }

	// Array application
	/*struct NeighInfos nInfos[m_nNeighborsValue];
	uint16_t j = 0;

	for(auto n :m_neighInfosVector){
		nInfos[j].ip = n.ip;
		nInfos[j].x = n.x;
		nInfos[j].y = n.y;
		nInfos[j].z = n.z; 
		nInfos[j].hop = n.hop;
		nInfos[j].state = n.state;
		j+=1;
	}
	
	unsigned char temp3[sizeof(NeighInfos) * m_nNeighborsValue];
	std::memcpy(temp3,nInfos,sizeof(NeighInfos) * m_nNeighborsValue);

	i.Write(temp3,sizeof(NeighInfos) * m_nNeighborsValue);*/

    // Array application
    if (actualNeighbors > 0) {
        size_t blockSize = sizeof(NeighInfos) * actualNeighbors;
        unsigned char* tempBuffer = new unsigned char[blockSize];
        
        std::memcpy(tempBuffer, m_neighInfosVector.data(), blockSize);
        
        i.Write(tempBuffer, blockSize);
        
        delete[] tempBuffer; 
    }
}

/**
 * @author Vinicius - MiM
 * @date Nov 17, 2025 
 * @brief Serialize tag data with encryption
 * @param i Tag data buffer
 * @param key Encryption key
 * @param nonce Encryption nonce
 */
void MyTag::Serialize(TagBuffer i, const std::string& key, const std::string& nonce) const
{
    NS_LOG_FUNCTION(this);
    // Serialize normally to a temporary buffer
    uint32_t clearSize = GetSerializedSize();
    uint8_t* clearBuffer = new uint8_t[clearSize];
    TagBuffer tempBuffer(clearBuffer, clearBuffer + clearSize);
    Serialize(tempBuffer); // Call the original serialization

    std::cout << "Serialize (Encryption): Original Data Size = " << clearSize << " bytes" << std::endl;

    // Prepare to encrypt
    uint32_t encryptedMaxSize = clearSize + CRYPTO_ABYTES;
    unsigned char* encryptedBuffer = new unsigned char[encryptedMaxSize];
    unsigned long long encryptedActualLen = 0;

    // Encrypt
    int res = crypto_aead_encrypt(encryptedBuffer, &encryptedActualLen,
                        clearBuffer, clearSize,
                        NULL, 0, // associated data is null
						NULL, // nsec
                        (const unsigned char*)nonce.c_str(),
                        (const unsigned char*)key.c_str());

    if (res != 0) {
        std::cout << "MyTag::Serialize (Encryption): Encryption FAILED! res=" << res << std::endl;
        // Fill with 0xFF to ensure Deserialize sees invalid magic number
        std::memset(encryptedBuffer, 0xFF, encryptedMaxSize);
        encryptedActualLen = encryptedMaxSize;
    }

    std::cout << "Serialize (Encryption): Encrypted Size = " << encryptedActualLen << " bytes (Overhead: " << (long long)(encryptedActualLen - clearSize) << ")" << std::endl;
    
    std::stringstream ss;
    for(unsigned long long k = 0; k < encryptedActualLen; k++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)encryptedBuffer[k];
    }
    std::cout<< "Encrypted Buffer (Hex): " << ss.str() << std::endl << std::endl;

    // Write the encrypted data to the final tag buffer
    i.Write(encryptedBuffer, encryptedActualLen);
    
    delete[] clearBuffer;
    delete[] encryptedBuffer;
}

/**
 * @brief This function reads data from a buffer and store it in class's instance variables.
 * @date Nov 10, 2022
 * @date Jan 19, 2023 (Everaldo - Include neigbhors list copy)
 * @date Jun 05, 2023 - Include message sent time to tag
 * 
 * @param i Tag data buffer
 */
void MyTag::Deserialize (TagBuffer i)
{
    uint8_t magic = i.ReadU8();
    if (magic != MY_TAG_MAGIC) {
        // If the byte does not match, the data is encrypted or corrupted
        std::cout << "MyTag: Invalid Magic Number! Aborting Deserialize to prevent crash." << std::endl;
        
        // Resets the tag to a safe state and returns
        m_simpleValue = 255;
        m_messageTime = 0;
        m_nNeighborsValue = 0;
        m_currentPosition = Vector(0,0,0);
        m_publicKey.clear();
        m_neighInfosVector.clear();
        return; 
    }

	m_simpleValue = i.ReadU8(); // Extract what we stored first, so we extract the tag value
	m_messageTime = i.ReadDouble(); // Extract the time message was sent
	m_nNeighborsValue = i.ReadU32(); // Extract the number of neighobrs value
    if (m_nNeighborsValue > 5000) { 
        m_nNeighborsValue = 0; 
    }
	m_currentPosition.x = i.ReadDouble(); // Extract position
	m_currentPosition.y = i.ReadDouble();
	m_currentPosition.z = i.ReadDouble();

	// Vinicius - MiM - Nov 13, 2025 - Extract public key
	uint32_t keySize = i.ReadU32();
    if (keySize > 2048) keySize = 0;

    if (keySize > 0) {
        uint8_t* buffer = new uint8_t[keySize];
        i.Read(buffer, keySize);
        m_publicKey.assign((char*)buffer, keySize);
        delete[] buffer;
    } else {
        m_publicKey.clear();
    }

    m_neighInfosVector.clear();

	// Arrarys application
	/*struct NeighInfos nInfos[m_nNeighborsValue];
	
	unsigned char temp3[sizeof(NeighInfos) * m_nNeighborsValue];
	i.Read(temp3,sizeof(NeighInfos) * m_nNeighborsValue);	
	memcpy(&nInfos,&temp3,sizeof(NeighInfos) * m_nNeighborsValue);

	m_neighInfosVector.clear();

	for(auto n :nInfos){
		NeighInfos node;
		node.ip = n.ip;
		node.x = n.x;
		node.y = n.y;
		node.z = n.z;
		node.hop = n.hop;
		node.state = n.state;
		m_neighInfosVector.push_back(node);
	}*/

    if (m_nNeighborsValue > 0) {
        size_t blockSize = sizeof(NeighInfos) * m_nNeighborsValue;
        unsigned char* tempBuffer = new unsigned char[blockSize];
        
        i.Read(tempBuffer, blockSize);   
        
        NeighInfos* nInfos = (NeighInfos*)tempBuffer;

        for(uint32_t k=0; k < m_nNeighborsValue; k++){
            NeighInfos node;
            node.ip = nInfos[k].ip;
            node.x = nInfos[k].x;
            node.y = nInfos[k].y;
            node.z = nInfos[k].z;
            node.hop = nInfos[k].hop;
            node.state = nInfos[k].state;
            m_neighInfosVector.push_back(node);
        }
        delete[] tempBuffer; 
    }
}

/**
 * @author Vinicius - MiM
 * @date Nov 17, 2025 
 * @brief Deserialize tag data with encryption
 * @param i Tag data buffer
 * @param key Encryption key
 * @param nonce Encryption nonce
 */
bool MyTag::Deserialize(TagBuffer i, const std::string& key, const std::string& nonce)
{
    NS_LOG_FUNCTION(this);

    // Get the encrypted data from the tag buffer
    uint32_t encryptedSize = i.GetSize();
    const uint8_t* encryptedBuffer = i.GetBuffer();

    std::cout << "Deserialize (Decryption): Received Encrypted Buffer Size = " << encryptedSize << " bytes" << std::endl;

    std::stringstream ss;
    for(uint32_t k = 0; k < encryptedSize; k++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)encryptedBuffer[k];
    }
    std::cout << "Received Buffer (Hex): " << ss.str() << std::endl;

    // Prepare to decrypt
    uint32_t decryptedMaxSize = encryptedSize;
    unsigned char* decryptedBuffer = new unsigned char[decryptedMaxSize];
    unsigned long long decryptedActualLen = 0;

    // Decrypt
    int ret = crypto_aead_decrypt(decryptedBuffer, &decryptedActualLen,
                                NULL, // nsec
                                encryptedBuffer, encryptedSize,
                                NULL, 0, // 'ad'
                                (const unsigned char*)nonce.c_str(),
                                (const unsigned char*)key.c_str());

    if (ret != 0) {
        delete[] decryptedBuffer;
        return false;
    }

    std::cout << "Deserialize (Decryption): Success! Decrypted Size = " << decryptedActualLen << " bytes" << std::endl << std::endl;

    // Deserialize the clear data
    TagBuffer clearBuffer(decryptedBuffer, decryptedBuffer + decryptedActualLen);
    Deserialize(clearBuffer); // Call the original deserialization

    delete[] decryptedBuffer;
    return true;
}

void MyTag::Print(std::ostream &os) const {
  std::cout << "Tag " << (uint32_t)m_simpleValue << std::endl;
}

/**
 * @brief Set the tag value
 * 
 * \param value The tag value
 */
void MyTag::SetSimpleValue(uint8_t value) {
	 m_simpleValue = value; 
}

/**
 * @brief Get the tag value
 * 
 * \return The tag value
 */

uint8_t MyTag::GetSimpleValue(void) const
{
   return m_simpleValue; 
}

/**
 * @brief Get nodes position
 * @date Nov 10, 2022
 * 
 * @return Vector with position values
 */
Vector MyTag::GetPosition(void) {
	return m_currentPosition;
}

/**
 * @brief Set nodes position
 * @date Nov 10, 2022
 * 
 * @param pos Position values
 */
void MyTag::SetPosition(Vector pos) {
	m_currentPosition = pos;
}

/**
 * @brief Get the number of neighbor nodes from the tag
 * @date 17112022
 * 
 * @return uint32_t Number of neighbor nodes
 */
uint32_t MyTag::GetNNeighbors(void){
	return m_nNeighborsValue;
}


/**
 * @brief Set the number of neighbor nodes in the tag
 * @date 17112022
 * 
 * @param nNeighbors Number of neighbor nodes
 */
void MyTag::SetNNeighbors (uint32_t nNeighbors){
	m_nNeighborsValue = nNeighbors;
} 


/**
 * @brief Get neighbor list vector from tag
 * @date 19012023
 * 
 * @return const vector<MyTag::NodeInfos>& 
 */
vector<MyTag::NeighInfos> MyTag::GetNeighInfosVector() const {
	return m_neighInfosVector;
}


/**
 * @brief Set a neighbor list vector in the tag
 * @date 19012023
 * 
 * @param NodeInfosVector Vector with a neighbor nodes list
 */
void MyTag::SetNeighInfosVector(const vector<MyTag::NeighInfos> neighInfosVector) {
	m_neighInfosVector = neighInfosVector;
}

/**
 * @brief Set message time to tag
 * @date 05062023
 * 
 * @param time Double message sent time
 */
void MyTag::SetMessageTime(double time){
 	m_messageTime = time;
}

/**
 * @brief Get message time to tag
 * @date 05062023
 * 
 * @return time Double message sent time
 */
double MyTag::GetMessageTime(){
 	return m_messageTime;
}


}  // namespace ns3

/* ------------------------------------------------------------------------
 * End of MyTag class
 * ------------------------------------------------------------------------
 */
