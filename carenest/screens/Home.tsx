import React from 'react';
import { ScrollView, View, Text, TouchableOpacity, Image, StyleSheet } from 'react-native';

const HomeScreen = () => {
  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Header Section */}
      <View style={styles.header}>
        <Text style={styles.title}>Home</Text>
        <Image source={require('./image.png')} style={styles.profilePic} resizeMode="contain" />
      </View>

      {/* Recipe Collection and Consult an Expert Section */}
      <View style={styles.row}>
        <TouchableOpacity style={styles.gridItem}>
          <Image source={require('./image2.png')} style={styles.gridIcon} resizeMode="contain" />
          <Text style={styles.gridText}>Recipe Collection</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.gridItem}>
          <Image source={require('./image3.png')} style={styles.gridIcon} resizeMode="contain" />
          <Text style={styles.gridText}>Consult an Expert</Text>
        </TouchableOpacity>
      </View>

      {/* Get Started Section */}
      <TouchableOpacity style={styles.getStartedSection}>
        <Image source={require('./image4.png')} style={styles.getStartedIcon} resizeMode="contain" />
        <Text style={styles.getStartedText}>Get Started</Text>
        <Text style={styles.subText}>Track Your Meals Today</Text>
      </TouchableOpacity>

      {/* Today's Food Coverage Section */}
      <View style={styles.foodCoverage}>
        <Text style={styles.subHeading}>Today's Food Coverage:</Text>
        <View style={styles.foodRow}>
          {['Fruit', 'Grains', 'Pulses', 'Veg', 'Dairy'].map((item) => {
            const images = {
              Fruit: require('./image5.png'),
              Grains: require('./image6.png'),
              Pulses: require('./image7.png'),
              Veg: require('./image8.png'),
              Dairy: require('./image9.png'),
            };
            return (
              <View style={styles.foodItem} key={item}>
                <Image source={images[item]} style={styles.foodIcon} resizeMode="contain" />
                <Text style={styles.foodText}>{item}</Text>
              </View>
            );
          })}
        </View>
      </View>

      {/* Grocery List Section */}
      <TouchableOpacity style={styles.largeSection}>
        <Image source={require('./image10.png')} style={styles.largeIcon} resizeMode="contain" />
        <Text style={styles.largeText}>Grocery List</Text>
      </TouchableOpacity>

      {/* Your Favourites and What's in Your Fridge? Section */}
      <View style={styles.row}>
        <TouchableOpacity style={styles.gridItem}>
          <Image source={require('./image11.png')} style={styles.gridIcon} resizeMode="contain" />
          <Text style={styles.gridText}>Your Favourites</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.gridItem}>
          <Image source={require('./image12.png')} style={styles.gridIcon} resizeMode="contain" />
          <Text style={styles.gridText}>What's in your fridge?</Text>
        </TouchableOpacity>
      </View>

      {/* Journey Tracker and Community Section */}
      <View style={styles.row}>
        <TouchableOpacity style={styles.gridItem}>
          <Image source={require('./image13.png')} style={styles.gridIcon} resizeMode="contain" />
          <Text style={styles.gridText}>Journey Tracker</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.gridItem}>
          <Image source={require('./image14.png')} style={styles.gridIcon} resizeMode="contain" />
          <Text style={styles.gridText}>Community</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 16,
    backgroundColor: '#FFF3D6',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  title: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#4C3B28',
  },
  profilePic: {
    width: 50,
    height: 50,
    borderRadius: 25,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  gridItem: {
    width: '48%',
    backgroundColor: '#FFEDD5',
    padding: 16,
    borderRadius: 15,
    alignItems: 'center',
    elevation: 3,
    marginBottom:50,
  },
  gridText: {
    marginTop: 8,
    fontSize: 16,
    color: '#4C3B28',
    textAlign: 'center',
  },
  gridIcon: {
    width: 60, // Consistent icon size for grid items
    height: 60,
  },
  getStartedSection: {
    backgroundColor: '#F0A6CA',
    padding: 20,
    borderRadius: 15,
    marginBottom: 20,
    alignItems: 'center',
  },
  getStartedIcon: {
    width: 70, // Increased for emphasis
    height: 70,
  },
  getStartedText: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#4C3B28',
  },
  subText: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
  },
  foodCoverage: {
    marginBottom: 20,
    padding: 15,
    backgroundColor: '#FFF',
    borderRadius: 15,
    elevation: 2,
  },
  subHeading: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#4C3B28',
    marginBottom: 10,
  },
  foodRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  foodItem: {
    alignItems: 'center',
    marginRight: 15,
  },
  foodIcon: {
    width: 45, // Smaller size for food icons
    height: 45,
  },
  foodText: {
    fontSize: 12,
    color: '#4C3B28',
    marginTop: 4,
  },
  largeSection: {
    backgroundColor: '#FFEDD5',
    padding: 20,
    borderRadius: 15,
    alignItems: 'center',
    marginBottom: 20,
  },
  largeIcon: {
    width: 60,
    height: 60,
  },
  largeText: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#4C3B28',
  },
});

export default HomeScreen;
