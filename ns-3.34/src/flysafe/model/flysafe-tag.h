#ifndef MYTAG_H
#define MYTAG_H

#include "ns3/tag.h"
#include "ns3/uinteger.h"
#include "ns3/vector.h"
#include "ns3/ipv4.h"

#include "ns3/crypto_aead.h"
#include "ns3/api.h"

using namespace std;

namespace ns3 {

class MyTag : public Tag {
public:
  static TypeId GetTypeId(void);
  virtual TypeId GetInstanceTypeId(void) const;
  virtual uint32_t GetSerializedSize(void) const;
  virtual void Serialize(TagBuffer i) const;
  virtual void Deserialize(TagBuffer i);
  virtual void Print(ostream &os) const;
  void SetSimpleValue(uint8_t value);
  uint8_t GetSimpleValue(void) const;

  // Vinicius - MiM - Nov 17, 2025
  virtual uint32_t GetSerializedSize(const std::string& key, const std::string& nonce) const;
  virtual void Serialize(TagBuffer i, const std::string& key, const std::string& nonce) const;
  virtual bool Deserialize(TagBuffer i, const std::string& key, const std::string& nonce);

  //These are custom accessor
	Vector GetPosition(void);                     //!< Get nodes position
	void SetPosition (Vector pos);                //!< Set nodes position
	uint32_t GetNNeighbors(void);                 //!< Get the number of neighbor nodes
	void SetNNeighbors (uint32_t nNeighbors);     //!< Set the number of neighbor nodes
  void SetMessageTime(double time);             //!< Set message sent time to tag
  double GetMessageTime();                      //!< Get message sent time to tag

  /**
   * @brief Struct to store infos from a neighbor node
   * @date 19012023
   */
  struct NeighInfos {
        Ipv4Address ip;
        double x;
        double y;
        double z;
        uint8_t hop;
        uint8_t state;
  };

  /**
   * \brief Neighbor entry.
   * This structure is used to store Neighbors' node information
   * @date 06042023
   */

  struct NeighborFull {
        Ipv4Address ip; //!< the neighbor IP address
        Vector position;
        double distance;
        uint8_t attitude;
        uint8_t quality;
        uint8_t hop; //!< hop = 1 means neighbor in range, 
        uint8_t state; // !< 0 ordinary, 1 suspicious
  }; 

  /**
   * \brief Malicious Neighbor entry
   * This structure is used to store malicious neighbors' node information
   * @date Nov 27, 2023
   */
  struct MaliciousNode{
        Ipv4Address ip;     //!< the neighbor IP address
        uint8_t state;      //!< 0 suspicious, 1 blocked
        uint8_t recurrence; //!< 1 - 3
        std::vector<Ipv4Address> notifyIP;
  }; 

  vector<NeighInfos> GetNeighInfosVector() const;
	void SetNeighInfosVector(const vector<NeighInfos> neighInfosVector);

  // Vinicius - MiM - Nov 13, 2025
  void SetPublicKey(const std::string& key) { m_publicKey = key; };
  std::string GetPublicKey() const { return m_publicKey; };

private:
  uint8_t m_simpleValue;                  //!< Tag value
  uint32_t m_nNeighborsValue;             //!< Number of neighbor nodes
	Vector m_currentPosition;               //!< Current position
  vector<NeighInfos> m_neighInfosVector;  //!< Store a list of neighbor nodes infos
  double m_messageTime;                   //!< Store message sent time
  // Vinicius - MiM - Nov 13, 2025
  std::string m_publicKey;                //!< Public key
};
} // namespace ns3

#endif