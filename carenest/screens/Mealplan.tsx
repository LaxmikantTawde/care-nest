import React from 'react';
import { View, Text, Image, TouchableOpacity, StyleSheet, ScrollView } from 'react-native';

const MealPlanScreen = () => {
  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerText}>Meal Plan</Text>
      </View>

      {/* Food Coverage */}
      <View style={styles.foodCoverage}>
        <Text style={styles.foodCoverageTitle}>Today's Food Coverage:</Text>
        <View style={styles.foodIcons}>
          {['🍎 Fruit', '🌾 Grains', '🍇 Pulses', '🍆 Veg', '🥛 Dairy'].map((item, index) => (
            <Text key={index} style={styles.foodIcon}>{item}</Text>
          ))}
        </View>
      </View>

      {/* Meal Sections */}
      {['Breakfast', 'Lunch', 'Dinner'].map((meal, index) => (
        <View
          key={index}
          style={[
            styles.mealSection,
            { backgroundColor: index === 0 ? '#FDE8CE' : index === 1 ? '#C2F8F3' : '#C9DDBA' },
          ]}
        >
          <Text style={styles.mealTitle}>🍞 {meal}</Text>
          <View style={styles.mealCard}>
            <Image
              source={{ uri: 'https://example.com/appam.jpg' }} // Replace with actual image URL
              style={styles.mealImage}
              resizeMode="cover"
            />
            <View style={styles.mealInfo}>
              <Text style={styles.mealName}>Appam</Text>
              <Text style={styles.mealDescription}>Tiffin Friendly, Energy Booster + 2 more.</Text>
              <View style={styles.mealTags}>
                <Text>⏲️ 15 Mins</Text>
                <Text>🌾 Grains</Text>
                <Text>🍇 Pulses</Text>
              </View>
            </View>
          </View>
        </View>
      ))}

      {/* Allergy Question */}
      <View style={styles.questionCard}>
        <Text style={styles.questionText}>Is Vishal allergic to paneer?</Text>
        <View style={styles.questionButtons}>
          <TouchableOpacity style={styles.yesButton}>
            <Text style={styles.buttonText}>Yes</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.noButton}>
            <Text style={styles.buttonText}>No</Text>
          </TouchableOpacity>
        </View>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: '#F4F6F8',
    paddingHorizontal: 16,
    paddingVertical: 20,
  },
  header: {
    backgroundColor: '#878FFF',
    padding: 20,
    borderRadius: 20,
    alignItems: 'center',
    marginBottom: 20,
  },
  headerText: {
    fontSize: 30, // Increased size for better visibility
    fontWeight: 'bold',
    color: '#FFFFFF',
  },
  foodCoverage: {
    backgroundColor: '#C8E6C9',
    borderRadius: 20,
    padding: 15,
    marginBottom: 20,
    elevation: 3, // Slightly stronger shadow
  },
  foodCoverageTitle: {
    fontSize: 22, // Increased font size for title
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#333333',
  },
  foodIcons: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    flexWrap: 'wrap',
  },
  foodIcon: {
    fontSize: 18,
    color: '#333333',
    margin: 5,
    backgroundColor: '#FFFFFF', // Added background for better contrast
    borderRadius: 10,
    padding: 5,
  },
  mealSection: {
    borderRadius: 20,
    padding: 15,
    marginBottom: 15,
    elevation: 3, // Slightly stronger shadow
  },
  mealTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#333333',
  },
  mealCard: {
    flexDirection: 'row',
    backgroundColor: '#FFFFE0',
    padding: 10,
    borderRadius: 15,
    elevation: 1,
  },
  mealImage: {
    width: 80,
    height: 80,
    borderRadius: 15,
    marginRight: 10,
  },
  mealInfo: {
    flex: 1,
  },
  mealName: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#333333',
  },
  mealDescription: {
    fontSize: 14,
    color: '#7B7B7B',
    marginBottom: 5,
  },
  mealTags: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 5,
  },
  questionCard: {
    backgroundColor: '#FFFFE0',
    padding: 20,
    borderRadius: 20,
    marginTop: 20,
    elevation: 3,
    marginBottom:60,
  },
  questionText: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#333333',
  },
  questionButtons: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  yesButton: {
    backgroundColor: '#F9B7B5',
    paddingVertical: 12,
    paddingHorizontal: 25,
    borderRadius: 20,
  },
  noButton: {
    backgroundColor: '#C4FFC1',
    paddingVertical: 12,
    paddingHorizontal: 25,
    borderRadius: 20,
  },
  buttonText: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333333',
  },
});

export default MealPlanScreen;
