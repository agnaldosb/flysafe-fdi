#include "flysafe-tag.h"
#include "ns3/vector.h"

/* ========================================================================
 * MyTag class
 *
 * Inherited from Tag class
 *
 * Create and add tags to packets
 *
 * ========================================================================
 */

namespace ns3 {

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
	return sizeof(Vector) + sizeof(uint8_t) + sizeof(uint32_t) + (sizeof(NeighInfos) * m_nNeighborsValue) + sizeof(double);
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

	i.WriteU8(m_simpleValue); // Store tag value first
	i.WriteDouble(m_messageTime); // Store message sent time 
	i.WriteU32(m_nNeighborsValue); // Store number of neighbors value
	i.WriteDouble (m_currentPosition.x); // Store the position
	i.WriteDouble (m_currentPosition.y);
	i.WriteDouble (m_currentPosition.z);

	// Array application
	struct NeighInfos nInfos[m_nNeighborsValue];
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

	i.Write(temp3,sizeof(NeighInfos) * m_nNeighborsValue);
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
	m_simpleValue = i.ReadU8(); // Extract what we stored first, so we extract the tag value
	m_messageTime = i.ReadDouble(); // Extract the time message was sent
	m_nNeighborsValue = i.ReadU32(); // Extract the number of neighobrs value
	m_currentPosition.x = i.ReadDouble(); // Extract position
	m_currentPosition.y = i.ReadDouble();
	m_currentPosition.z = i.ReadDouble();

	// Arrarys application
	struct NeighInfos nInfos[m_nNeighborsValue];
	
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
	}
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
