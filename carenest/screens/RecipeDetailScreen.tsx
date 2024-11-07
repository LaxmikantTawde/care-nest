import React from 'react';
import { View, Text, Image, TouchableOpacity, StyleSheet, ScrollView } from 'react-native';

const RecipePage = () => {
  return (
    <ScrollView style={styles.container}>
      {/* Header with Image and Title */}
      <View style={styles.header}>
        <Image
          source={{ uri: 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRgGqYDbaTNjbDpRVCXM4kWp1TuSrCu-sxrEA&s' }} // Replace with actual image URL
          style={styles.recipeImage}
        />
        <Text style={styles.recipeTitle}>Apple Rice Porridge</Text>
      </View>

      {/* Tags Section */}
      <View style={styles.tagsContainer}>
        <View style={styles.tag}>
          <Text style={styles.tagText}>20 Min</Text>
        </View>
        <View style={styles.tag}>
          <Text style={styles.tagText}>Fruit</Text>
        </View>
        <View style={styles.tag}>
          <Text style={styles.tagText}>Fiber-Rich</Text>
        </View>
      </View>

      {/* Nutritional Information */}
      <View style={styles.nutritionContainer}>
        <View style={styles.nutritionItem}>
          <Text style={styles.nutritionLabel}>Fat</Text>
          <Text style={styles.nutritionValue}>0.2g</Text>
        </View>
        <View style={styles.nutritionItem}>
          <Text style={styles.nutritionLabel}>Protein</Text>
          <Text style={styles.nutritionValue}>1.2g</Text>
        </View>
        <View style={styles.nutritionItem}>
          <Text style={styles.nutritionLabel}>Carbs</Text>
          <Text style={styles.nutritionValue}>32.5g</Text>
        </View>
        <View style={styles.nutritionItem}>
          <Text style={styles.nutritionLabel}>Fiber</Text>
          <Text style={styles.nutritionValue}>2.6g</Text>
        </View>
      </View>

      {/* Ingredients Section */}
      <View style={styles.ingredientsContainer}>
        <Text style={styles.sectionTitle}>Ingredients</Text>
        <Text style={styles.ingredientItem}>Apple (pureed)</Text>
        <Text style={styles.ingredientItem}>Date Powder (as is)</Text>
        <Text style={styles.ingredientItem}>Ghee</Text>
        <Text style={styles.ingredientItem}>Cinnamon</Text>
        <Text style={styles.ingredientItem}>Rice</Text>
      </View>

      {/* Instructions Section */}
      <View style={styles.instructionsContainer}>
        <Text style={styles.sectionTitle}>Instructions</Text>
        <Text style={styles.instructionItem}>1. Rinse the rice under cold water until the water runs clear.</Text>
        <Text style={styles.instructionItem}>2. Combine rice and water in a pot and bring to a boil.</Text>
        <Text style={styles.instructionItem}>3. Reduce heat to low, cover, and simmer for about 20 minutes or until the rice is tender.</Text>
        <Text style={styles.instructionItem}>4. Add the chopped apple, mix, honey (if using), cinnamon, and salt to the pot.</Text>
        <Text style={styles.instructionItem}>5. Cook for another 10 minutes, stirring occasionally, until the apple is soft and the porridge has thickened.</Text>
        <Text style={styles.instructionItem}>6. Serve warm, optionally topped with additional cinnamon or a drizzle of honey.</Text>
      </View>

      {/* Buttons Section */}
      <View style={styles.buttonsContainer}>
        <TouchableOpacity style={styles.button}>
          <Text style={styles.buttonText}>Try Today</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.button}>
          <Text style={styles.buttonText}>Meal Plan</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#F4F4F4', // Light background for better contrast
  },
  header: {
    alignItems: 'center',
    marginBottom: 20,
  },
  recipeImage: {
    width: '100%', // Full width image for better display
    height: 200,
    borderRadius: 15,
    marginBottom: 10,
    borderWidth: 2,
    borderColor: '#FFBB33', // Border color for the image
  },
  recipeTitle: {
    fontSize: 26,
    fontWeight: 'bold',
    color: '#4C4F50',
    textAlign: 'center', // Center the title
  },
  tagsContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    marginBottom: 20,
  },
  tag: {
    backgroundColor: '#FFE79A',
    padding: 10,
    borderRadius: 10,
    marginHorizontal: 5,
    elevation: 2, // Slight elevation for depth
  },
  tagText: {
    color: '#333',
    fontWeight: '600',
  },
  nutritionContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  nutritionItem: {
    alignItems: 'center',
  },
  nutritionLabel: {
    fontWeight: 'bold',
    color: '#555',
  },
  nutritionValue: {
    color: '#777',
  },
  ingredientsContainer: {
    marginBottom: 20,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#4C4F50',
  },
  ingredientItem: {
    fontSize: 16,
    marginBottom: 5,
    color: '#555',
  },
  instructionsContainer: {
    marginBottom: 20,
  },
  instructionItem: {
    fontSize: 16,
    marginBottom: 5,
    color: '#555',
  },
  buttonsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  button: {
    backgroundColor: '#A8F2A3',
    padding: 10,
    borderRadius: 10,
    alignItems: 'center',
    width: '45%',
    elevation: 3,
    marginBottom:50, // Button elevation for depth
  },
  buttonText: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#333', // Dark text for contrast
  },
});

export default RecipePage;
