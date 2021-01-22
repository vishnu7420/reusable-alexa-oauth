'use strict';
module.exports = {
    up: async(queryInterface, Sequelize) => {
        await queryInterface.createTable('users', {
            id: {
                allowNull: false,
                autoIncrement: true,
                primaryKey: true,
                type: Sequelize.INTEGER
            },
            firebase_uid: {
                type: Sequelize.STRING
            },
            first_name: {
                allowNull: true,
                type: Sequelize.STRING
            },
            last_name: {
                allowNull: true,
                type: Sequelize.STRING
            },
            first_name: {
                allowNull: true,
                type: Sequelize.STRING
            },
            email: {
                type: Sequelize.STRING
            },
            phone_no: {
                type: Sequelize.STRING
            },
            password: {
                unique: true,
                type: Sequelize.STRING
            },
            createdAt: {
                allowNull: false,
                type: Sequelize.DATE,
                defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
        
        
              },
              updatedAt: {
                allowNull: false,
                type: Sequelize.DATE,
                defaultValue: Sequelize.literal('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP')
              }
        });
    },
    down: async(queryInterface, Sequelize) => {
        await queryInterface.dropTable('users');
    }
};